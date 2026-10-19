package sysmon

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

func hideWindow(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

func decodeBytes(b []byte) string {
	if len(b) >= 2 {
		if b[0] == 0xFF && b[1] == 0xFE {
			return decodeUTF16(b[2:], true)
		}
		if b[0] == 0xFE && b[1] == 0xFF {
			return decodeUTF16(b[2:], false)
		}
	}
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}
	if looksUTF16(b) {
		if len(b)%2 == 1 && b[0] == 0x00 {
			b = b[1:]
		}
		return decodeUTF16(b, true)
	}
	if utf8.Valid(b) {
		return string(b)
	}
	return decodeANSI(b)
}

func looksUTF16(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	nul := 0
	for _, c := range b {
		if c == 0 {
			nul++
		}
	}
	return nul*4 > len(b)
}

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procMultiByteToWide = kernel32.NewProc("MultiByteToWideChar")
	procCreateMutexW    = kernel32.NewProc("CreateMutexW")

	user32          = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")

	versionDLL                  = syscall.NewLazyDLL("version.dll")
	procGetFileVersionInfoSizeW = versionDLL.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW     = versionDLL.NewProc("GetFileVersionInfoW")
	procVerQueryValueW          = versionDLL.NewProc("VerQueryValueW")
)

const errorAlreadyExists = 183

// TryLockSingleInstance 尝试创建命名互斥体；返回 false 表示已有实例在运行。
func TryLockSingleInstance(name string) bool {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return true
	}
	_, _, callErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(n)))
	if en, ok := callErr.(syscall.Errno); ok && en == errorAlreadyExists {
		return false
	}
	return true
}

// MessageBox 弹出系统信息对话框 (windowsgui 模式下没有控制台，用它提示关键错误)。
func MessageBox(title, text string) {
	t, _ := syscall.UTF16PtrFromString(title)
	x, _ := syscall.UTF16PtrFromString(text)
	const mbOK = 0
	const mbIconInformation = 0x40
	const mbTopmost = 0x40000
	_, _, _ = procMessageBoxW.Call(0, uintptr(unsafe.Pointer(t)), uintptr(unsafe.Pointer(x)), mbOK|mbIconInformation|mbTopmost)
}

// FileVersion 读取文件的 ProductVersion 资源，用于确定 Sysmon 版本。
func FileVersion(path string) string {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	size, _, _ := procGetFileVersionInfoSizeW.Call(uintptr(unsafe.Pointer(p)), 0)
	if size == 0 {
		return ""
	}
	buf := make([]byte, size)
	ret, _, _ := procGetFileVersionInfoW.Call(uintptr(unsafe.Pointer(p)), 0, size, uintptr(unsafe.Pointer(&buf[0])))
	if ret == 0 {
		return ""
	}
	lang := "040904b0"
	var tp unsafe.Pointer
	var tl uintptr
	kp, _ := syscall.UTF16PtrFromString(`\VarFileInfo\Translation`)
	ret, _, _ = procVerQueryValueW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(kp)), uintptr(unsafe.Pointer(&tp)), uintptr(unsafe.Pointer(&tl)))
	if ret != 0 && tl >= 4 {
		t := (*[2]uint16)(tp)
		lang = fmt.Sprintf("%04x%04x", t[0], t[1])
	}
	var vp unsafe.Pointer
	var vl uintptr
	sp, _ := syscall.UTF16PtrFromString(`\StringFileInfo\` + lang + `\ProductVersion`)
	ret, _, _ = procVerQueryValueW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(sp)), uintptr(unsafe.Pointer(&vp)), uintptr(unsafe.Pointer(&vl)))
	if ret == 0 || vl == 0 {
		return ""
	}
	u := (*[4096]uint16)(vp)
	return strings.TrimSpace(syscall.UTF16ToString(u[:vl]))
}

const cpGBK = 936

func decodeANSI(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	ret, _, _ := procMultiByteToWide.Call(
		uintptr(cpGBK),
		0,
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		0, 0,
	)
	n := int(ret)
	if n <= 0 {
		return string(b)
	}
	u := make([]uint16, n)
	ret, _, _ = procMultiByteToWide.Call(
		uintptr(cpGBK),
		0,
		uintptr(unsafe.Pointer(&b[0])),
		uintptr(len(b)),
		uintptr(unsafe.Pointer(&u[0])),
		uintptr(n),
	)
	if int(ret) <= 0 {
		return string(b)
	}
	return string(utf16.Decode(u))
}

// DecodeConsoleBytes 解码 Windows 控制台程序输出 (UTF-8 / UTF-16 / ANSI-GBK 自适应)。
func DecodeConsoleBytes(b []byte) string {
	return decodeBytes(b)
}

func decodeUTF16(b []byte, little bool) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		if little {
			u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
		} else {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		}
	}
	return string(utf16.Decode(u))
}

func execWithTimeout(cmd *exec.Cmd, timeout time.Duration) (string, string, error) {
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return "", "", err
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return decodeBytes(stdout.Bytes()), decodeBytes(stderr.Bytes()), err
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		return decodeBytes(stdout.Bytes()), decodeBytes(stderr.Bytes()), fmt.Errorf("命令超时 (%v)", timeout)
	}
}

// RunCmdWithTimeout 执行命令并限时，返回解码后的 stdout/stderr，供其他包复用。
func RunCmdWithTimeout(cmd *exec.Cmd, timeout time.Duration) (string, string, error) {
	return execWithTimeout(cmd, timeout)
}

var (
	shell32           = syscall.NewLazyDLL("shell32.dll")
	procIsUserAnAdmin = shell32.NewProc("IsUserAnAdmin")

	advapi32                = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken    = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = advapi32.NewProc("GetTokenInformation")
)

const (
	tokenQuery     = 0x8
	tokenElevation = 20
)

func tokenElevated() bool {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	var token syscall.Handle
	ret, _, _ := procOpenProcessToken.Call(uintptr(h), tokenQuery, uintptr(unsafe.Pointer(&token)))
	if ret == 0 {
		return false
	}
	defer syscall.CloseHandle(token)
	var elev struct{ TokenIsElevated uint32 }
	var retLen uint32
	ret, _, _ = procGetTokenInformation.Call(uintptr(token), tokenElevation, uintptr(unsafe.Pointer(&elev)), unsafe.Sizeof(elev), uintptr(unsafe.Pointer(&retLen)))
	return ret != 0 && elev.TokenIsElevated != 0
}

func shellIsUserAnAdmin() bool {
	if err := procIsUserAnAdmin.Find(); err != nil {
		return false
	}
	ret, _, _ := procIsUserAnAdmin.Call()
	return ret != 0
}

func netSessionAdmin() bool {
	cmd := exec.Command("net", "session")
	hideWindow(cmd)
	return cmd.Run() == nil
}

func AdminDetail() (elevated bool, detail string) {
	t := tokenElevated()
	s := shellIsUserAnAdmin()
	return t || s, fmt.Sprintf("token=%v IsUserAnAdmin=%v netsession=%v", t, s, netSessionAdmin())
}

// AdminDetailFast 与 AdminDetail 相同但跳过 net session 子进程，用于高频轮询。
func AdminDetailFast() (bool, string) {
	t := tokenElevated()
	s := shellIsUserAnAdmin()
	return t || s, fmt.Sprintf("token=%v IsUserAnAdmin=%v", t, s)
}

func IsAdmin() bool {
	v, _ := AdminDetail()
	return v
}

var (
	logMu   sync.Mutex
	logPath string
)

func SetLogPath(p string) {
	logMu.Lock()
	defer logMu.Unlock()
	logPath = p
	if fi, err := os.Stat(p); err == nil && fi.Size() > 512*1024 {
		os.WriteFile(p, nil, 0644)
	}
}

// LogPath 返回当前日志文件路径（供 API 读取运行日志）。
func LogPath() string {
	logMu.Lock()
	defer logMu.Unlock()
	return logPath
}

func Logf(format string, args ...interface{}) {
	logMu.Lock()
	defer logMu.Unlock()
	if logPath == "" {
		return
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

var procShellExecuteW = shell32.NewProc("ShellExecuteW")

// SelfElevate 以 runas 方式重新启动自身以弹出 UAC 提权窗口，用户同意返回 true。
func SelfElevate(exePath, params string) bool {
	verb, err := syscall.UTF16PtrFromString("runas")
	if err != nil {
		return false
	}
	file, err := syscall.UTF16PtrFromString(exePath)
	if err != nil {
		return false
	}
	par, err := syscall.UTF16PtrFromString(params)
	if err != nil {
		return false
	}
	const swShownormal = 1
	ret, _, _ := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(par)),
		0,
		uintptr(swShownormal),
	)
	return ret > 32
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

type Manager struct {
	mu          sync.Mutex
	dataDir     string
	exePath     string
	serviceName string
}

type Status struct {
	Installed     bool   `json:"installed"`
	Running       bool   `json:"running"`
	Version       string `json:"version"`
	ServiceName   string `json:"service_name"`
	ImpostorService string `json:"impostor_service,omitempty"` // 存在同名但非正版的 Sysmon 服务
	ExePath       string `json:"exe_path"`
	ExeExists     bool   `json:"exe_exists"`
	ExeVersion    string `json:"exe_version,omitempty"`
	ConfigPath    string `json:"config_path"`
	ConfigExists  bool   `json:"config_exists"`
	ConfigSize    int64  `json:"config_size"`
	ConfigModTime string `json:"config_mod_time"`
}

type OpResult struct {
	Success      bool     `json:"success"`
	Message      string   `json:"message"`
	Steps        []string `json:"steps"`
	Raw          []string `json:"raw,omitempty"`
	Errors       []string `json:"errors,omitempty"`
	ConfigErrors []string `json:"config_errors,omitempty"`
	TookMs       int64    `json:"took_ms"`
}

func NewManager(dataDir string) *Manager {
	m := &Manager{dataDir: dataDir}
	m.exePath = findSysmonExe(dataDir)
	return m
}

func findSysmonExe(dataDir string) string {
	if p := os.Getenv("SYSMON_EXE"); p != "" && fileExists(p) {
		return p
	}
	names := []string{"Sysmon64.exe", "Sysmon64a.exe", "Sysmon.exe"}
	if runtime.GOARCH == "386" {
		names = []string{"Sysmon.exe", "Sysmon64a.exe", "Sysmon64.exe"}
	}
	dirs := []string{dataDir, filepath.Join(dataDir, "sysmon"), filepath.Join(dataDir, "third_party", "sysmon")}
	for _, d := range dirs {
		for _, n := range names {
			p := filepath.Join(d, n)
			if fileExists(p) {
				return p
			}
		}
	}
	if runtime.GOARCH == "arm64" {
		return filepath.Join(dataDir, "Sysmon64a.exe")
	}
	return filepath.Join(dataDir, "Sysmon64.exe")
}

func (m *Manager) ExePath() string {
	return m.exePath
}

func (m *Manager) ConfigPath() string {
	return filepath.Join(m.dataDir, "sysmon-config.xml")
}

type svcState struct {
	name     string
	present  bool
	running  bool
	binPath  string
	genuine  bool
}

// isGenuineSysmonPath 判断服务映像路径是否为正版 Sysmon：
// 必须位于系统目录 (%SystemRoot%) 下且文件名以 sysmon 开头。
// 用于排除第三方软件注册的同名服务（如 eTrust SdpDns 的 C:\Program Files (x86)\eTrust\SdpDns\sysmon.sys）。
func isGenuineSysmonPath(p string) bool {
	if p == "" {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(p))
	lower = strings.TrimPrefix(lower, `\??\`)
	sysRoot := strings.ToLower(os.Getenv("SystemRoot"))
	if sysRoot == "" {
		sysRoot = `c:\windows`
	}
	sysRoot = strings.TrimSuffix(sysRoot, `\`)
	lower = strings.Replace(lower, `\systemroot\`, sysRoot+`\`, 1)
	if lower != sysRoot && !strings.HasPrefix(lower, sysRoot+`\`) {
		return false
	}
	base := lower
	if i := strings.LastIndexAny(base, `\/`); i >= 0 {
		base = base[i+1:]
	}
	return strings.HasPrefix(base, "sysmon")
}

func inspectService(name string) svcState {
	st := svcState{name: name}
	cmd := exec.Command("sc.exe", "query", name)
	hideWindow(cmd)
	out, _ := cmd.Output()
	s := decodeBytes(out)
	if strings.Contains(s, "RUNNING") || strings.Contains(s, "STOPPED") || strings.Contains(s, "PENDING") {
		st.present = true
		st.running = strings.Contains(s, "RUNNING") || strings.Contains(s, "START_PENDING")
	} else {
		return st
	}
	qc := exec.Command("sc.exe", "qc", name)
	hideWindow(qc)
	qcOut, _ := qc.Output()
	for _, line := range strings.Split(decodeBytes(qcOut), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "BINARY_PATH_NAME") {
			idx := strings.Index(line, ":")
			if idx == -1 {
				continue
			}
			st.binPath = strings.Trim(strings.TrimSpace(line[idx+1:]), `"`)
		}
	}
	st.genuine = isGenuineSysmonPath(st.binPath)
	return st
}

// findSysmonService 依次查找 Sysmon 服务：优先返回正版服务；否则返回第一个存在的（用于冒名提示）。
func findSysmonService() svcState {
	var firstPresent svcState
	for _, sn := range []string{"Sysmon64", "Sysmon64a", "Sysmon"} {
		st := inspectService(sn)
		if !st.present {
			continue
		}
		if st.genuine {
			return st
		}
		if !firstPresent.present {
			firstPresent = st
		}
	}
	return firstPresent
}

func parseVersion(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		idx := strings.Index(line, "System Monitor v")
		if idx == -1 {
			continue
		}
		ver := strings.TrimSpace(line[idx+len("System Monitor v"):])
		end := strings.IndexAny(ver, " \t(-")
		if end > 0 {
			ver = ver[:end]
		}
		if ver != "" {
			return ver
		}
	}
	return ""
}

func (m *Manager) detectVersion(exePath string) string {
	cmd := exec.Command(exePath, "-c")
	hideWindow(cmd)
	out, _, err := execWithTimeout(cmd, 30*time.Second)
	if err == nil {
		if v := parseVersion(out); v != "" {
			return v
		}
	}
	cmd = exec.Command(exePath, "-?")
	hideWindow(cmd)
	out, _, err = execWithTimeout(cmd, 15*time.Second)
	if err == nil {
		return parseVersion(out)
	}
	return ""
}

func (m *Manager) CheckStatus() Status {
	st := Status{
		ExePath:    m.exePath,
		ConfigPath: m.ConfigPath(),
	}
	st.ExeExists = fileExists(m.exePath)
	if st.ExeExists {
		st.ExeVersion = FileVersion(m.exePath)
	}
	svc := findSysmonService()
	m.mu.Lock()
	m.serviceName = ""
	if svc.genuine {
		m.serviceName = svc.name
	}
	m.mu.Unlock()
	st.Installed = svc.genuine
	st.Running = svc.genuine && svc.running
	st.ServiceName = m.serviceName
	if svc.present && !svc.genuine {
		st.ImpostorService = fmt.Sprintf("%s (%s)", svc.name, svc.binPath)
	}
	if fi, err := os.Stat(st.ConfigPath); err == nil {
		st.ConfigExists = true
		st.ConfigSize = fi.Size()
		st.ConfigModTime = fi.ModTime().Format("2006-01-02 15:04:05")
	}
	if st.Installed {
		if p := m.serviceBinPath(); p != "" {
			if v := FileVersion(p); v != "" {
				st.Version = v
			}
		}
		if st.Version == "" && st.ExeExists {
			if v := m.detectVersion(m.exePath); v != "" {
				st.Version = v
			}
		}
	}
	return st
}

func (m *Manager) serviceBinPath() string {
	svc := findSysmonService()
	if !svc.genuine {
		return ""
	}
	if svc.binPath != "" && fileExists(svc.binPath) {
		return svc.binPath
	}
	return ""
}

func (m *Manager) resolveExe() (string, error) {
	if fileExists(m.exePath) {
		return m.exePath, nil
	}
	if p := m.serviceBinPath(); p != "" {
		return p, nil
	}
	return "", fmt.Errorf("未找到 Sysmon 可执行文件: %s (可将 Sysmon64.exe 放到程序同目录，或设置环境变量 SYSMON_EXE)", m.exePath)
}

func isAccessDenied(out, errOut string) bool {
	s := strings.ToLower(out + " " + errOut)
	return strings.Contains(s, "access is denied") ||
		strings.Contains(s, "access denied") ||
		strings.Contains(s, "as an administrator") ||
		strings.Contains(out, "拒绝访问") ||
		strings.Contains(errOut, "拒绝访问") ||
		strings.Contains(out, "管理员") ||
		strings.Contains(errOut, "管理员")
}

func compact(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func addRaw(res *OpResult, prefix, s string) {
	if s = compact(s); s != "" {
		res.Raw = append(res.Raw, prefix+s)
	}
}

func (m *Manager) Install(configPath string, ruleGroupCount int) *OpResult {
	start := time.Now()
	res := &OpResult{}
	Logf("Install 开始: config=%s 规则组=%d", configPath, ruleGroupCount)
	defer func() {
		Logf("Install 结束: success=%v msg=%s 耗时=%dms", res.Success, res.Message, time.Since(start).Milliseconds())
	}()
	exe, err := m.resolveExe()
	if err != nil {
		res.Message = err.Error()
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	if !fileExists(configPath) {
		msg := fmt.Sprintf("配置文件不存在: %s", configPath)
		res.Message = msg
		res.Errors = append(res.Errors, msg)
		return res
	}

	svc := findSysmonService()
	if svc.genuine {
		res.Steps = append(res.Steps, fmt.Sprintf("检测到已安装的正版 Sysmon 服务 (%s)，跳过安装步骤", svc.name))
	} else {
		if svc.present {
			res.Steps = append(res.Steps, fmt.Sprintf("忽略同名非正版服务 %s (%s)，执行全新安装", svc.name, svc.binPath))
		}
		runInstall := func() error {
			cmd := exec.Command(exe, "-i", "-accepteula")
			hideWindow(cmd)
			out, errOut, err := execWithTimeout(cmd, 120*time.Second)
			addRaw(res, "[安装 -i] ", out)
			addRaw(res, "[安装 -i] ", errOut)
			if err != nil {
				detail := compact(errOut)
				if detail == "" {
					detail = compact(out)
				}
				if isAccessDenied(out, errOut) {
					detail = "需要管理员权限，请以管理员身份运行本程序"
				}
				return fmt.Errorf("%s (%v)", detail, err)
			}
			return nil
		}
		installErr := runInstall()
		// 半安装残留（服务已注册但装到一半失败）会导致 -i 报 "already registered"，自动清理后重试一次
		if installErr != nil && strings.Contains(strings.ToLower(fmt.Sprint(installErr)), "already registered") {
			res.Steps = append(res.Steps, "检测到半安装残留，自动执行 -u force 清理后重试")
			uc := exec.Command(exe, "-u", "force")
			hideWindow(uc)
			uOut, uErrOut, _ := execWithTimeout(uc, 120*time.Second)
			addRaw(res, "[清理 -u] ", uOut)
			addRaw(res, "[清理 -u] ", uErrOut)
			installErr = runInstall()
		}
		if installErr != nil {
			if st := findSysmonService(); !st.genuine {
				res.Message = "Sysmon 安装失败: " + installErr.Error()
				res.Errors = append(res.Errors, installErr.Error())
				res.TookMs = time.Since(start).Milliseconds()
				return res
			}
			res.Steps = append(res.Steps, "安装命令报告错误，但检测到正版服务已存在，继续应用配置: "+installErr.Error())
		} else {
			res.Steps = append(res.Steps, "Sysmon 服务安装成功")
		}
	}

	cmd := exec.Command(exe, "-c", configPath)
	hideWindow(cmd)
	out, errOut, err := execWithTimeout(cmd, 120*time.Second)
	addRaw(res, "[应用配置 -c] ", out)
	addRaw(res, "[应用配置 -c] ", errOut)
	if err != nil {
		detail := compact(errOut)
		if detail == "" {
			detail = err.Error()
		}
		if isAccessDenied(out, errOut) {
			detail = "需要管理员权限，请以管理员身份运行本程序"
		}
		res.Message = "Sysmon 配置应用失败: " + detail
		res.Errors = append(res.Errors, detail)
		res.TookMs = time.Since(start).Milliseconds()
		return res
	}

	// 最终校验：配置应用成功不代表服务真的在（历史上 -c 在未安装时也可能退出码 0）
	verify := findSysmonService()
	if !verify.genuine {
		msg := "配置已生成并提交，但未检测到正版 Sysmon 服务（可能存在同名第三方服务干扰或安装中途失败），建议执行「重新安装」"
		res.Message = msg
		res.Errors = append(res.Errors, msg)
		res.TookMs = time.Since(start).Milliseconds()
		return res
	}
	res.Steps = append(res.Steps, fmt.Sprintf("校验通过：正版服务 %s 已安装", verify.name))
	if !verify.running {
		running := false
		for i := 0; i < 3; i++ {
			time.Sleep(time.Second)
			if s := findSysmonService(); s.genuine && s.running {
				running = true
				break
			}
		}
		if !running {
			res.Steps = append(res.Steps, "警告: Sysmon 服务处于停止状态（驱动可能被安全软件或系统策略阻止加载），请检查系统事件日志")
		}
	}

	res.Success = true
	res.Message = fmt.Sprintf("Sysmon 安装并应用配置成功（%d 个规则组）", ruleGroupCount)
	res.Steps = append(res.Steps, fmt.Sprintf("配置应用成功：%d 个规则组", ruleGroupCount))
	res.TookMs = time.Since(start).Milliseconds()
	return res
}

func (m *Manager) Uninstall() *OpResult {
	start := time.Now()
	res := &OpResult{}
	Logf("Uninstall 开始")
	defer func() {
		Logf("Uninstall 结束: success=%v msg=%s 耗时=%dms", res.Success, res.Message, time.Since(start).Milliseconds())
	}()
	svc := findSysmonService()
	if !svc.genuine {
		res.Success = true
		if svc.present {
			res.Message = fmt.Sprintf("未检测到正版 Sysmon 服务（%s 为同名第三方服务，已忽略），无需卸载", svc.name)
		} else {
			res.Message = "Sysmon 尚未安装，无需卸载"
		}
		res.Steps = append(res.Steps, "未检测到正版 Sysmon 服务")
		return res
	}
	exe, err := m.resolveExe()
	if err != nil {
		res.Message = err.Error()
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	cmd := exec.Command(exe, "-u", "force")
	hideWindow(cmd)
	out, errOut, err := execWithTimeout(cmd, 120*time.Second)
	addRaw(res, "[卸载 -u] ", out)
	addRaw(res, "[卸载 -u] ", errOut)
	if err != nil {
		if findSysmonService().genuine {
			detail := compact(errOut)
			if isAccessDenied(out, errOut) {
				detail = "需要管理员权限，请以管理员身份运行本程序"
			}
			res.Message = "Sysmon 卸载失败: " + detail
			res.Errors = append(res.Errors, detail)
			res.TookMs = time.Since(start).Milliseconds()
			return res
		}
		res.Steps = append(res.Steps, "服务已不存在，视为卸载成功")
	}
	res.Success = true
	res.Message = "Sysmon 已卸载"
	res.Steps = append(res.Steps, "Sysmon 服务已卸载")
	res.TookMs = time.Since(start).Milliseconds()
	return res
}

func (m *Manager) Reinstall(configPath string, ruleGroupCount int) *OpResult {
	start := time.Now()
	un := m.Uninstall()
	if !un.Success {
		return un
	}
	re := m.Install(configPath, ruleGroupCount)
	re.Steps = append(un.Steps, re.Steps...)
	re.Raw = append(append([]string{}, un.Raw...), re.Raw...)
	re.TookMs = time.Since(start).Milliseconds()
	if re.Success {
		re.Message = "Sysmon 重新安装成功: " + re.Message
	}
	return re
}
