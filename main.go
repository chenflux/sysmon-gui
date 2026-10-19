package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"sysmon-gui/internal/api"
	"sysmon-gui/internal/sysmon"
	"sysmon-gui/internal/version"

	webview "github.com/jchv/go-webview2"
)

func openBrowser(url string) {
	cmd := exec.Command("cmd", "/c", "start", "", url)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = cmd.Start()
}

func runWindow(url, title, dataDir string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("WebView2 初始化失败: %v", r)
		}
	}()
	w := webview.NewWithOptions(webview.WebViewOptions{
		Debug:    false,
		DataPath: filepath.Join(dataDir, "webview2-data-v2"),
	})
	defer w.Destroy()
	w.SetTitle(title)
	w.SetSize(1360, 900, webview.HintNone)
	w.Navigate(url)
	w.Run()
	return nil
}

func quoteArg(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `'`) + `"`
}

func listen(addr string, explicit bool) (net.Listener, error) {
	var ln net.Listener
	var err error
	if explicit {
		for i := 0; i < 20; i++ {
			ln, err = net.Listen("tcp", addr)
			if err == nil {
				return ln, nil
			}
			time.Sleep(500 * time.Millisecond)
		}
		return nil, err
	}
	ln, err = net.Listen("tcp", addr)
	if err == nil {
		return ln, nil
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

func tryTakeoverExisting(addr string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/api/status")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var r struct {
		OK   bool `json:"ok"`
		Data struct {
			IsAdmin bool `json:"is_admin"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&r) != nil || !r.OK {
		return false
	}
	if r.Data.IsAdmin {
		return false
	}
	req, _ := http.NewRequest("POST", "http://"+addr+"/api/shutdown", nil)
	if _, err := client.Do(req); err != nil {
		return false
	}
	fmt.Println("检测到非管理员旧实例，已通知其退出")
	return true
}

const mutexName = `Local\sysmon-gui-singleton-v1`

func acquireSingleInstance(addr, mode string) bool {
	if sysmon.TryLockSingleInstance(mutexName) {
		return true
	}
	if sysmon.IsAdmin() && tryTakeoverExisting(addr) {
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if sysmon.TryLockSingleInstance(mutexName) {
				return true
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	if mode != "none" {
		sysmon.MessageBox("Sysmon GUI", "已有一个 Sysmon GUI 实例正在运行。\n\n请使用已打开的窗口；如需重启请先关闭它（关闭窗口即退出）。")
	}
	return false
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8791", "HTTP 监听地址")
	uiMode := flag.String("ui", "window", "界面模式: window=独立窗口 (默认), web=系统浏览器, none=无界面")
	noBrowser := flag.Bool("no-browser", false, "等同于 -ui none (兼容旧参数)")
	noElevate := flag.Bool("no-elevate", false, "跳过自动申请管理员权限 (UAC)")
	dataDir := flag.String("data", "", "数据目录 (默认为程序所在目录，存放 rules.json 与 sysmon-config.xml)")
	flag.Parse()

	mode := *uiMode
	if *noBrowser {
		mode = "none"
	}
	if mode != "window" && mode != "web" && mode != "none" {
		mode = "window"
	}

	dir := *dataDir
	if dir == "" {
		exePath, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "无法获取程序路径:", err)
			os.Exit(1)
		}
		dir = filepath.Dir(exePath)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		absDir = dir
	}

	sysmon.SetLogPath(filepath.Join(absDir, "sysmon-gui.log"))
	admin, adminDetail := sysmon.AdminDetail()
	sysmon.Logf("启动: 版本=%s pid=%d 模式=%s addr=%s 数据目录=%s 管理员=%v (%s)", version.String(), os.Getpid(), mode, *addr, absDir, admin, adminDetail)

	if !*noElevate && !admin {
		if exePath, err := os.Executable(); err == nil {
			params := fmt.Sprintf("-addr %s -data %s", quoteArg(*addr), quoteArg(absDir))
			if mode != "window" {
				params += " -ui " + mode
			}
			if sysmon.SelfElevate(exePath, params) {
				sysmon.Logf("非管理员启动，UAC 提权请求已受理，当前实例退出")
				fmt.Println("已弹出 UAC 授权窗口，当前实例退出，由管理员实例接管")
				return
			}
			sysmon.Logf("非管理员启动，未获得 UAC 授权，以普通权限继续")
			fmt.Println("未获得管理员权限，将以普通权限运行（仅支持查看状态与日志，安装/卸载不可用）")
		}
	}

	if !acquireSingleInstance(*addr, mode) {
		sysmon.Logf("退出: 已有实例在运行 (pid=%d)", os.Getpid())
		os.Exit(0)
	}

	mgr := sysmon.NewManager(absDir)

	addrExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "addr" {
			addrExplicit = true
		}
	})
	ln, err := listen(*addr, addrExplicit)
	if err != nil {
		sysmon.Logf("退出: 监听 %s 失败: %v", *addr, err)
		fmt.Fprintf(os.Stderr, "监听 %s 失败: %v\n", *addr, err)
		sysmon.MessageBox("Sysmon GUI", fmt.Sprintf("监听 %s 失败: %v", *addr, err))
		os.Exit(1)
	}
	sysmon.Logf("监听就绪: %s", ln.Addr().String())

	server := api.New(mgr, absDir, ln.Addr().String(), mode)
	url := fmt.Sprintf("http://%s", ln.Addr().String())
	fmt.Printf("Sysmon GUI 已启动: %s (界面模式: %s)\n", url, mode)
	fmt.Printf("数据目录: %s\n", absDir)

	go func() {
		if err := http.Serve(ln, server.Routes()); err != nil {
			fmt.Fprintln(os.Stderr, "服务退出:", err)
			os.Exit(1)
		}
	}()

	if mode == "window" {
		if err := runWindow(url, "Sysmon GUI - 部署与日志查看", absDir); err != nil {
			sysmon.Logf("窗口创建失败，回退浏览器: %v", err)
			fmt.Println(err)
			fmt.Println("回退到系统浏览器模式")
			openBrowser(url)
			select {}
		}
		sysmon.Logf("窗口关闭，进程退出")
		os.Exit(0)
	}
	if mode == "web" {
		openBrowser(url)
	}
	select {}
}
