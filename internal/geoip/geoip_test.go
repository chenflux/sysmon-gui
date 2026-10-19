package geoip

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalResolve(t *testing.T) {
	cases := map[string]string{
		"192.168.1.10":  "priv",
		"10.0.0.5":      "priv",
		"172.16.0.1":    "priv",
		"127.0.0.1":     "loopback",
		"169.254.1.1":   "linklocal",
		"239.255.255.250": "multicast",
		"0.0.0.0":       "unspecified",
	}
	for ip, wantCode := range cases {
		info, ok := localResolve(ip)
		if !ok {
			t.Fatalf("%s 应被本地识别，不触发在线查询", ip)
		}
		if info.Code != wantCode {
			t.Fatalf("%s code = %s, 期望 %s", ip, info.Code, wantCode)
		}
	}
	if _, ok := localResolve("8.8.8.8"); ok {
		t.Fatalf("公网 IP 不应被本地判定")
	}
	if _, ok := localResolve("not-an-ip"); ok {
		t.Fatalf("非法 IP 不应被判定")
	}
}

func TestLookupServesLocalWithoutNetwork(t *testing.T) {
	r := New(filepath.Join(t.TempDir(), "cache.json"))
	out := r.Lookup([]string{"192.168.1.10", "127.0.0.1", "192.168.1.10"})
	if len(out) != 2 {
		t.Fatalf("私网 IP 应去重后本地返回 2 条, got %d", len(out))
	}
	if out["192.168.1.10"].Code != "priv" || out["127.0.0.1"].Code != "loopback" {
		t.Fatalf("本地判定结果错误: %v", out)
	}
}

func TestCachePruneOnLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cache.json")
	now := time.Now().Unix()
	fresh := now - 86400            // 1 天前，仍在 TTL 内
	stale := now - int64(91*24*time.Hour/time.Second) // 91 天前，应被剪枝
	init := map[string]cacheEntry{
		"1.1.1.1": {Country: "Fresh", Code: "AU", FetchedAt: fresh},
		"2.2.2.2": {Country: "Stale", Code: "XX", FetchedAt: stale},
	}
	data, _ := json.Marshal(init)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	r := New(p)
	if _, hit := r.cache["2.2.2.2"]; hit {
		t.Fatalf("过期条目应在加载时被剪枝")
	}
	if _, hit := r.cache["1.1.1.1"]; !hit {
		t.Fatalf("未过期条目不应被剪枝")
	}
}
