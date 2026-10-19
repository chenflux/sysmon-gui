package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"sysmon-gui/internal/events"
	"sysmon-gui/internal/geoip"
	"sysmon-gui/internal/sysmon"
	"sysmon-gui/internal/version"
	"sysmon-gui/web"
)

type Server struct {
	mgr       *sysmon.Manager
	dataDir   string
	rulesPath string
	addr      string
	uiMode    string
	geo       *geoip.Resolver
}

func New(mgr *sysmon.Manager, dataDir string, addr string, uiMode string) *Server {
	return &Server{
		mgr:       mgr,
		dataDir:   dataDir,
		rulesPath: filepath.Join(dataDir, "rules.json"),
		addr:      addr,
		uiMode:    uiMode,
		geo:       geoip.New(filepath.Join(dataDir, "geoip-cache.json")),
	}
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func ok(w http.ResponseWriter, data interface{}) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "data": data})
}

func fail(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]interface{}{"ok": false, "error": msg})
}

type noStoreHandler struct{ h http.Handler }

func (n noStoreHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	n.h.ServeHTTP(w, r)
}

// hostAllowed 校验请求的 Host 是否为本机回环地址（防 DNS rebinding）。
func hostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	h := host
	if _, port, err := net.SplitHostPort(host); err == nil && port != "" {
		h = strings.Trim(host[:len(host)-len(port)-1], "[]")
	} else {
		h = strings.Trim(h, "[]")
	}
	switch h {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

// originAllowed 校验写操作请求来源（防浏览器 CSRF）。
// 浏览器 (Chromium) 会发送 Origin 与 Sec-Fetch-Site；非浏览器工具两者皆无，保持放行。
func originAllowed(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none", "":
		// ok
	default:
		return false // cross-site / same-site 均拒绝
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		u, err := url.ParseRequestURI(origin)
		if err != nil || !hostAllowed(u.Host) {
			return false
		}
	}
	return true
}

// securityMiddleware 本地 API 安全校验：Host 白名单 + 非 GET 请求的来源校验。
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host) {
			fail(w, http.StatusForbidden, "拒绝访问: 非法 Host (仅允许本机回环地址)")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			if !originAllowed(r) {
				fail(w, http.StatusForbidden, "拒绝跨站请求")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/meta", s.handleMeta)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/rules", s.handleGetRules)
	mux.HandleFunc("GET /api/rules/deployed", s.handleGetDeployedRules)
	mux.HandleFunc("PUT /api/rules", s.handlePutRules)
	mux.HandleFunc("POST /api/rules/preview", s.handlePreview)
	mux.HandleFunc("GET /api/config.xml", s.handleDownloadXML)
	mux.HandleFunc("POST /api/sysmon/install", s.handleInstall)
	mux.HandleFunc("POST /api/sysmon/uninstall", s.handleUninstall)
	mux.HandleFunc("POST /api/sysmon/reinstall", s.handleReinstall)
	mux.HandleFunc("POST /api/sysmon/download", s.handleSysmonDownload)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("GET /api/events.csv", s.handleEventsCSV)
	mux.HandleFunc("GET /api/events/xml", s.handleEventXML)
	mux.HandleFunc("GET /api/events/process-tree", s.handleProcessTree)
	mux.HandleFunc("POST /api/geoip", s.handleGeoIP)
	mux.HandleFunc("GET /api/geoip/status", s.handleGeoIPStatus)
	mux.HandleFunc("GET /api/applog", s.handleAppLog)
	mux.HandleFunc("POST /api/shutdown", s.handleShutdown)
	mux.HandleFunc("POST /api/elevate", s.handleElevate)
	mux.HandleFunc("POST /api/rules/validate", s.handleValidate)
	mux.HandleFunc("POST /api/rules/import-xml", s.handleImportXML)
	mux.Handle("/", http.FileServer(http.FS(web.FS)))
	return noStoreHandler{securityMiddleware(mux)}
}

func (s *Server) handleImportXML(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		fail(w, http.StatusBadRequest, "读取请求体失败: "+err.Error())
		return
	}
	if len(data) == 0 {
		fail(w, http.StatusBadRequest, "请求体为空，请提供 Sysmon 配置 XML 内容")
		return
	}
	s.respondImport(w, data)
}

func (s *Server) respondImport(w http.ResponseWriter, data []byte) {
	cfg, condCount, err := sysmon.ParseSysmonXML(data)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := 0
	for _, rr := range cfg.Rules {
		if rr.Enabled {
			enabled++
		}
	}
	ok(w, map[string]interface{}{
		"config":        cfg,
		"rules_total":   len(cfg.Rules),
		"rules_enabled": enabled,
		"cond_total":    condCount,
		"lint":          sysmon.LintRules(cfg, s.mgr.Schema()),
	})
}

func (s *Server) handleElevate(w http.ResponseWriter, r *http.Request) {
	if isAdmin, detail := sysmon.AdminDetailFast(); isAdmin {
		sysmon.Logf("elevate: 已是管理员 (%s)", detail)
		ok(w, map[string]string{"message": "当前已是管理员权限"})
		return
	}
	exePath, err := os.Executable()
	if err != nil {
		fail(w, http.StatusInternalServerError, "无法获取程序路径: "+err.Error())
		return
	}
	params := fmt.Sprintf("-addr %s -data %s", quoteArg(s.addr), quoteArg(s.dataDir))
	if s.uiMode != "window" {
		params += " -ui " + s.uiMode
	}
	if sysmon.SelfElevate(exePath, params) {
		sysmon.Logf("elevate: UAC 已弹出，本实例即将退出")
		ok(w, map[string]string{"message": "已弹出 UAC 授权窗口，同意后本程序将以管理员身份重启"})
		go func() {
			time.Sleep(time.Second)
			os.Exit(0)
		}()
		return
	}
	sysmon.Logf("elevate: UAC 被取消或被拒绝")
	fail(w, http.StatusForbidden, "未获得管理员授权（UAC 被取消或被系统策略禁止）")
}

func quoteArg(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `'`) + `"`
}

func countActiveGroups(cfg *sysmon.RuleConfig) (rules int, groups int) {
	for _, r := range cfg.Rules {
		if !r.Enabled {
			continue
		}
		rules++
		n := 0
		for _, g := range r.Groups {
			for _, c := range g.Conditions {
				if c != nil && strings.TrimSpace(c.Field) != "" && len(c.Values) > 0 {
					n++
					break
				}
			}
			if n > 0 {
				groups++
			}
			n = 0
		}
	}
	return rules, groups
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	var cfg sysmon.RuleConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		fail(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	lint := sysmon.LintRules(&cfg, s.mgr.Schema())
	xmlWellFormed := true
	if xmlStr, err := sysmon.GenerateXML(&cfg); err != nil {
		xmlWellFormed = false
		lint.Errors = append(lint.Errors, "生成配置 XML 失败: "+err.Error())
	} else {
		var probe struct{}
		if err := xml.Unmarshal([]byte(xmlStr), &probe); err != nil {
			xmlWellFormed = false
			lint.Errors = append(lint.Errors, "生成的 XML 语法无效: "+err.Error())
		}
	}
	rules, groups := countActiveGroups(&cfg)
	ok(w, map[string]interface{}{
		"valid":           len(lint.Errors) == 0,
		"xml_well_formed": xmlWellFormed,
		"rules_total":     rules,
		"groups_total":    groups,
		"issues":          lint,
	})
}

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	sysmon.Logf("收到退出请求")
	ok(w, map[string]string{"message": "程序即将退出"})
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
}

func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	schema := s.mgr.Schema()
	static := sysmon.EventTypes()
	out := map[string]interface{}{
		"operators":     sysmon.Operators(),
		"eid_names":     sysmon.EIDNames,
		"app_version":   version.String(),
		"schema_source": "内置清单 (未加载 Sysmon schema)",
		"event_types":   static,
	}
	if !schema.FromSysmon {
		ok(w, out)
		return
	}
	eidByType := map[string]int{}
	for _, t := range static {
		eidByType[t.Type] = t.EventID
	}
	labelByType := map[string]string{}
	for _, t := range static {
		labelByType[t.Type] = t.Label
	}
	seen := map[string]bool{}
	merged := []sysmon.EventTypeInfo{}
	for _, t := range static {
		if fields, ok := schema.Fields[t.Type]; ok {
			seen[t.Type] = true
			merged = append(merged, sysmon.EventTypeInfo{Type: t.Type, Label: t.Label, EventID: t.EventID, Fields: fields})
		}
	}
	for t, fields := range schema.Fields {
		if seen[t] {
			continue
		}
		merged = append(merged, sysmon.EventTypeInfo{Type: t, Label: labelByType[t], EventID: eidByType[t], Fields: fields})
	}
	out["event_types"] = merged
	out["schema_source"] = fmt.Sprintf("Sysmon 官方 schema v%s (binary v%s)", schema.SchemaVer, schema.BinaryVer)
	ok(w, out)
}

func (s *Server) rulesHash() string {
	data, err := os.ReadFile(s.rulesPath)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s *Server) deployedHashPath() string {
	return filepath.Join(s.dataDir, "deployed.hash")
}

func (s *Server) markDeployed() {
	_ = os.WriteFile(s.deployedHashPath(), []byte(s.rulesHash()), 0644)
	// 快照当前已部署的规则，供「查看差异」对比
	if data, err := os.ReadFile(s.rulesPath); err == nil {
		_ = os.WriteFile(filepath.Join(s.dataDir, "rules-deployed.json"), data, 0644)
	}
}

func (s *Server) handleGetDeployedRules(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(filepath.Join(s.dataDir, "rules-deployed.json"))
	if err != nil {
		ok(w, map[string]interface{}{"available": false})
		return
	}
	var cfg sysmon.RuleConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		ok(w, map[string]interface{}{"available": false})
		return
	}
	ok(w, map[string]interface{}{"available": true, "rules": cfg})
}

func (s *Server) handleAppLog(w http.ResponseWriter, r *http.Request) {
	p := sysmon.LogPath()
	if p == "" {
		fail(w, http.StatusNotFound, "日志未初始化")
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		fail(w, http.StatusNotFound, "读取日志失败: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *Server) rulesDirty(installed bool) bool {
	if !installed {
		return false
	}
	dep, err := os.ReadFile(s.deployedHashPath())
	if err != nil {
		return true
	}
	return string(dep) != s.rulesHash()
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := s.mgr.CheckStatus()
	rules, err := sysmon.LoadRules(s.rulesPath)
	enabled := 0
	if err == nil {
		for _, rr := range rules.Rules {
			if rr.Enabled {
				enabled++
			}
		}
	}
	isAdmin, adminDetail := sysmon.AdminDetailFast()
	ok(w, map[string]interface{}{
		"status":        st,
		"is_admin":      isAdmin,
		"admin_detail":  adminDetail,
		"rules_total":   len(rules.Rules),
		"rules_enabled": enabled,
		"rules_dirty":   s.rulesDirty(st.Installed),
	})
}

func (s *Server) handleGetRules(w http.ResponseWriter, r *http.Request) {
	cfg, err := sysmon.LoadRules(s.rulesPath)
	if err != nil {
		fail(w, http.StatusInternalServerError, "加载规则失败: "+err.Error())
		return
	}
	if _, err := os.Stat(s.rulesPath); os.IsNotExist(err) {
		_ = sysmon.SaveRules(s.rulesPath, cfg)
	}
	ok(w, cfg)
}

func (s *Server) handlePutRules(w http.ResponseWriter, r *http.Request) {
	var cfg sysmon.RuleConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		fail(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	for _, rule := range cfg.Rules {
		if rule.ID == "" {
			rule.ID = sysmon.NewRuleID()
		}
	}
	if err := sysmon.ValidateConfig(&cfg, s.mgr.Schema()); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := sysmon.SaveRules(s.rulesPath, &cfg); err != nil {
		fail(w, http.StatusInternalServerError, "保存规则失败: "+err.Error())
		return
	}
	ok(w, map[string]interface{}{"rules_total": len(cfg.Rules)})
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request) {
	var cfg sysmon.RuleConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		fail(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	if err := sysmon.ValidateConfig(&cfg, s.mgr.Schema()); err != nil {
		fail(w, http.StatusBadRequest, "规则无效: "+err.Error())
		return
	}
	xmlStr, err := sysmon.GenerateXML(&cfg)
	if err != nil {
		fail(w, http.StatusInternalServerError, "生成 XML 失败: "+err.Error())
		return
	}
	ok(w, map[string]string{"xml": xmlStr})
}

func (s *Server) ensureConfigXML() (string, int, error) {
	cfg, err := sysmon.LoadRules(s.rulesPath)
	if err != nil {
		cfg = sysmon.DefaultRuleConfig()
	}
	xmlStr, err := sysmon.GenerateXML(cfg)
	if err != nil {
		return "", 0, err
	}
	p := s.mgr.ConfigPath()
	if err := os.WriteFile(p, []byte(xmlStr), 0644); err != nil {
		return "", 0, err
	}
	_, groups := countActiveGroups(cfg)
	return p, groups, nil
}

func (s *Server) handleDownloadXML(w http.ResponseWriter, r *http.Request) {
	cfg, err := sysmon.LoadRules(s.rulesPath)
	if err != nil {
		fail(w, http.StatusInternalServerError, "加载规则失败: "+err.Error())
		return
	}
	xmlStr, err := sysmon.GenerateXML(cfg)
	if err != nil {
		fail(w, http.StatusInternalServerError, "生成 XML 失败: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", "attachment; filename=sysmon-config.xml")
	_, _ = w.Write([]byte(xmlStr))
}

func (s *Server) handleInstall(w http.ResponseWriter, r *http.Request) {
	configPath, groups, err := s.ensureConfigXML()
	if err != nil {
		fail(w, http.StatusInternalServerError, "生成配置文件失败: "+err.Error())
		return
	}
	res := s.mgr.Install(configPath, groups)
	if res.Success {
		s.markDeployed()
	} else {
		s.attachLint(w, res)
		return
	}
	ok(w, res)
}

func (s *Server) attachLint(w http.ResponseWriter, res *sysmon.OpResult) {
	cfg, err := sysmon.LoadRules(s.rulesPath)
	if err == nil {
		lint := sysmon.LintRules(cfg, s.mgr.Schema())
		if len(lint.Errors) > 0 {
			res.ConfigErrors = lint.Errors
		}
	}
	ok(w, res)
}

func (s *Server) handleUninstall(w http.ResponseWriter, r *http.Request) {
	ok(w, s.mgr.Uninstall())
}

func (s *Server) handleReinstall(w http.ResponseWriter, r *http.Request) {
	configPath, groups, err := s.ensureConfigXML()
	if err != nil {
		fail(w, http.StatusInternalServerError, "生成配置文件失败: "+err.Error())
		return
	}
	res := s.mgr.Reinstall(configPath, groups)
	if res.Success {
		s.markDeployed()
	}
	ok(w, res)
}

// handleSysmonDownload 从微软 Sysinternals 官网下载 Sysmon 并解压到程序目录。
func (s *Server) handleSysmonDownload(w http.ResponseWriter, r *http.Request) {
	if isAdmin, _ := sysmon.AdminDetailFast(); !isAdmin {
		fail(w, http.StatusForbidden, "下载并写入 Sysmon 需要管理员权限，请以管理员身份运行本程序")
		return
	}
	extracted, err := sysmon.DownloadSysmonTo(s.mgr.DataDir())
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.mgr.RefreshExePath()
	st := s.mgr.CheckStatus()
	ok(w, map[string]interface{}{
		"extracted":  extracted,
		"exe_exists": st.ExeExists,
		"exe_path":   st.ExePath,
		"version":    st.ExeVersion,
	})
}

func parseEventOptions(r *http.Request) events.Options {
	q := r.URL.Query()
	atoi := func(key string) int {
		v := q.Get(key)
		if v == "" {
			return 0
		}
		n, _ := strconv.Atoi(v)
		return n
	}
	since := int64(0)
	if v := q.Get("since_record_id"); v != "" {
		since, _ = strconv.ParseInt(v, 10, 64)
	}
	return events.Options{
		EventID:       atoi("event_id"),
		Keyword:       q.Get("keyword"),
		Hours:         atoi("hours"),
		Fetch:         atoi("fetch"),
		Page:          atoi("page"),
		PageSize:      atoi("page_size"),
		SinceRecordID: since,
	}
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	opts := parseEventOptions(r)
	result, err := events.Query(opts)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok(w, result)
}

func (s *Server) handleEventsCSV(w http.ResponseWriter, r *http.Request) {
	opts := parseEventOptions(r)
	opts.Page = 1
	opts.PageSize = events.MaxFetch
	result, err := events.Query(opts)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	data := events.ToCSV(result.Events)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=sysmon-events-%s.csv", r.URL.Query().Get("event_id")))
	_, _ = w.Write(data)
}

func (s *Server) handleEventXML(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.URL.Query().Get("record_id"), 10, 64)
	if err != nil || id <= 0 {
		fail(w, http.StatusBadRequest, "缺少有效的 record_id 参数")
		return
	}
	xmlText, ok := events.GetEventXML(id)
	if !ok {
		fail(w, http.StatusNotFound, "该事件的原始 XML 不在缓存中（仅原生 API 最近拉取的事件可查）")
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(xmlText))
}

func (s *Server) handleProcessTree(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	guid := strings.TrimSpace(q.Get("guid"))
	if guid == "" {
		fail(w, http.StatusBadRequest, "缺少 guid 参数 (ProcessGuid)")
		return
	}
	if len(guid) > 100 {
		fail(w, http.StatusBadRequest, "guid 参数无效")
		return
	}
	fetch, _ := strconv.Atoi(q.Get("fetch"))
	if fetch <= 0 {
		fetch = 5000
	}
	if fetch > events.MaxFetch {
		fetch = events.MaxFetch
	}
	hours, _ := strconv.Atoi(q.Get("hours"))
	res, err := events.ProcessTree(guid, fetch, hours)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	ok(w, res)
}

func (s *Server) handleGeoIP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IPs []string `json:"ips"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, "请求体解析失败: "+err.Error())
		return
	}
	if len(body.IPs) == 0 {
		fail(w, http.StatusBadRequest, "ips 列表为空")
		return
	}
	if len(body.IPs) > 1000 {
		fail(w, http.StatusBadRequest, "单次最多查询 1000 个 IP")
		return
	}
	ok(w, s.geo.Lookup(body.IPs))
}

func (s *Server) handleGeoIPStatus(w http.ResponseWriter, r *http.Request) {
	loaded, dbType := s.geo.MMDBInfo()
	dir := s.dataDir
	ok(w, map[string]interface{}{
		"mmdb_loaded": loaded,
		"mmdb_type":   dbType,
		"hint": fmt.Sprintf("将 GeoLite2-City.mmdb 或 GeoLite2-Country.mmdb 放到 %s 即可离线解析（无需在线接口，不外发 IP）", dir),
	})
}
