package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sysmon-gui/internal/sysmon"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := New(sysmon.NewManager(t.TempDir()), t.TempDir(), "127.0.0.1:8791", "none")
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	return srv
}

func doReq(t *testing.T, srv *httptest.Server, method, path, host, origin, sfs string) int {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader([]byte(`{}`)))
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if sfs != "" {
		req.Header.Set("Sec-Fetch-Site", sfs)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestSecurityMiddlewareHostAllowlist(t *testing.T) {
	srv := newTestServer(t)
	cases := []struct {
		host string
		code int
	}{
		{"127.0.0.1:8791", 200},
		{"localhost:8791", 200},
		{"[::1]:8791", 200},
		{"evil.com", 403},
		{"127.0.0.1.evil.com", 403},
		{"10.0.0.5:8791", 403},
	}
	for _, c := range cases {
		if got := doReq(t, srv, "GET", "/", c.host, "", ""); got != c.code {
			t.Errorf("Host %q: GET / = %d, 期望 %d", c.host, got, c.code)
		}
	}
}

func TestSecurityMiddlewareWriteProtection(t *testing.T) {
	srv := newTestServer(t)
	const host = "127.0.0.1:8791"
	cases := []struct {
		name   string
		origin string
		sfs    string
		code   int // 403=拦截; 400=通过中间件到达 handler(空 body 解析失败)
	}{
		{"无浏览器头(工具客户端)", "", "", 400},
		{"同源 Origin", "http://127.0.0.1:8791", "", 400},
		{"同源 Sec-Fetch-Site", "", "same-origin", 400},
		{"跨站 Origin", "http://evil.com", "", 403},
		{"跨站 Sec-Fetch-Site", "", "cross-site", 403},
		{"同域不同源", "", "same-site", 403},
		{"Origin null", "null", "", 403},
	}
	for _, c := range cases {
		if got := doReq(t, srv, "POST", "/api/geoip", host, c.origin, c.sfs); got != c.code {
			t.Errorf("%s: POST /api/geoip = %d, 期望 %d", c.name, got, c.code)
		}
	}
}

func TestGeoIPEndpointValidation(t *testing.T) {
	srv := newTestServer(t)
	req, _ := http.NewRequest("POST", srv.URL+"/api/geoip", bytes.NewReader([]byte(`{"ips":["192.168.0.1"]}`)))
	req.Host = "127.0.0.1:8791"
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		OK   bool           `json:"ok"`
		Data map[string]geo `json:"data"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != 200 || !out.OK {
		t.Fatalf("GeoIP 私网查询应成功: status=%d ok=%v", resp.StatusCode, out.OK)
	}
	if g := out.Data["192.168.0.1"]; g.Code != "priv" {
		t.Fatalf("私网 IP 应本地判定: %+v", g)
	}
}

type geo struct {
	Country string `json:"country"`
	Code    string `json:"code"`
}

/* ---- handler 覆盖测试（兼容无 Sysmon 的 CI 环境） ---- */

func getJSON(t *testing.T, url string) (int, map[string]interface{}) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestHandlerMeta(t *testing.T) {
	srv := newTestServer(t)
	code, out := getJSON(t, srv.URL+"/api/meta")
	if code != 200 || out["ok"] != true {
		t.Fatalf("meta: status=%d ok=%v", code, out["ok"])
	}
	data := out["data"].(map[string]interface{})
	if data["app_version"] == nil || data["event_types"] == nil || data["operators"] == nil {
		t.Fatalf("meta 缺少必要字段: %#v", data)
	}
}

func TestHandlerRulesRoundtrip(t *testing.T) {
	srv := newTestServer(t)
	// GET 默认
	code, out := getJSON(t, srv.URL+"/api/rules")
	if code != 200 || out["ok"] != true {
		t.Fatalf("rules GET: %d", code)
	}
	// PUT 一条规则
	body := `{"schema_version":"4.90","rules":[{"id":"t1","name":"测试","event_type":"ProcessCreate","on_match":"include","enabled":true,"note":"","groups":[{"relation":"and","conditions":[{"field":"Image","op":"contains","values":["abc.exe"]}]}]}]}`
	req, _ := http.NewRequest("PUT", srv.URL+"/api/rules", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("rules PUT: %d", resp.StatusCode)
	}
	// 再 GET 验证持久化
	_, out2 := getJSON(t, srv.URL+"/api/rules")
	rules := out2["data"].(map[string]interface{})["rules"].([]interface{})
	if len(rules) != 1 {
		t.Fatalf("rules 往返失败: %#v", rules)
	}
}

func TestHandlerValidateAndPreview(t *testing.T) {
	srv := newTestServer(t)
	body := `{"rules":[{"id":"v1","name":"校验","event_type":"NetworkConnect","on_match":"include","enabled":true,"note":"","groups":[{"relation":"and","conditions":[{"field":"DestinationIp","op":"is","values":["1.2.3.4"]}]}]}]}`
	resp, _ := http.Post(srv.URL+"/api/rules/validate", "application/json", strings.NewReader(body))
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	if resp.StatusCode != 200 || out["ok"] != true {
		t.Fatalf("validate: %d %#v", resp.StatusCode, out)
	}
	resp2, _ := http.Post(srv.URL+"/api/rules/preview", "application/json", strings.NewReader(body))
	var out2 map[string]interface{}
	_ = json.NewDecoder(resp2.Body).Decode(&out2)
	resp2.Body.Close()
	xmlStr, _ := out2["data"].(map[string]interface{})["xml"].(string)
	if !strings.Contains(xmlStr, "<Sysmon") || !strings.Contains(xmlStr, "1.2.3.4") {
		t.Fatalf("preview XML 应包含 Sysmon 根节点与条件值: %.200s", xmlStr)
	}
}

func TestHandlerAppLogAndDeployed(t *testing.T) {
	srv := newTestServer(t)
	// applog：日志未初始化 → 404
	resp, _ := http.Get(srv.URL + "/api/applog")
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("applog 未初始化应 404, got %d", resp.StatusCode)
	}
	// deployed：无快照 → available=false
	_, out := getJSON(t, srv.URL+"/api/rules/deployed")
	data := out["data"].(map[string]interface{})
	if data["available"] != false {
		t.Fatalf("deployed 默认应为 false: %#v", data)
	}
}

func TestHandlerTemplates(t *testing.T) {
	srv := newTestServer(t)
	_, out := getJSON(t, srv.URL+"/api/templates")
	arr := out["data"].([]interface{})
	if len(arr) < 1 {
		t.Fatalf("templates 应返回内置模板列表")
	}
}

func TestHandlerEventsFamilyOnNoSysmon(t *testing.T) {
	srv := newTestServer(t)
	// 无 Sysmon 的 CI 环境: /api/events 返回 ok:false + 友好错误；有 Sysmon 的环境则 200。两者皆可接受。
	code, out := getJSON(t, srv.URL+"/api/events?fetch=10")
	if code != 200 && code != 500 {
		t.Fatalf("events: 意外状态码 %d", code)
	}
	if code == 500 && out["ok"] != false {
		t.Fatalf("events 失败应返回 ok:false")
	}
	// process-tree 缺参 → 400
	resp, _ := http.Get(srv.URL + "/api/events/process-tree")
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("process-tree 缺参应 400, got %d", resp.StatusCode)
	}
	// events/xml 非法 record_id → 400
	resp2, _ := http.Get(srv.URL + "/api/events/xml?record_id=abc")
	resp2.Body.Close()
	if resp2.StatusCode != 400 {
		t.Fatalf("events/xml 非法参数应 400, got %d", resp2.StatusCode)
	}
}

func TestHandlerGeoIPStatus(t *testing.T) {
	srv := newTestServer(t)
	_, out := getJSON(t, srv.URL+"/api/geoip/status")
	data := out["data"].(map[string]interface{})
	if _, ok := data["mmdb_loaded"]; !ok {
		t.Fatalf("geoip/status 缺少 mmdb_loaded: %#v", data)
	}
}

func TestHandlerConfigXML(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/api/config.xml")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("config.xml: %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "<sysmon") && !strings.Contains(string(body), "<Sysmon") {
		t.Fatalf("config.xml 内容异常: %.100s", body)
	}
}
