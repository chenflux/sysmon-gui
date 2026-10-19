package geoip

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Info 单个 IP 的归属地查询结果。Code 为 ISO 3166-1 alpha-2 国家代码；
// 私网/回环等地址的 Code 为 priv/loopback/linklocal 等本地标记。
// Lat/Lon 仅在离线 City 库命中时返回（供地图打点）。
type Info struct {
	Country string   `json:"country"`
	Code    string   `json:"code"`
	Lat     *float64 `json:"lat,omitempty"`
	Lon     *float64 `json:"lon,omitempty"`
}

type cacheEntry struct {
	Country   string `json:"country"`
	Code      string `json:"code"`
	FetchedAt int64  `json:"ts"`
}

const (
	cacheTTL   = 30 * 24 * time.Hour
	pruneTTL   = 90 * 24 * time.Hour // 超过该时长未命中的缓存条目在加载时清除
	batchSize  = 100
	maxUnknown = 500 // 单次请求最多在线查询的未知 IP 数（ip-api 免费额度 15 请求/分钟）
	endpoint   = "http://ip-api.com/batch?fields=status,message,country,countryCode"
)

// Resolver 带本地磁盘缓存在线 GeoIP 解析器（ip-api.com 批量接口）。
// 若发现离线 mmdb 库（GeoLite2-City/Country）则优先离线解析，完全不外发 IP。
type Resolver struct {
	mu        sync.Mutex
	cachePath string
	cache     map[string]cacheEntry
	client    *http.Client
	mmdb      *MMDB
	mmdbType  string
}

func New(cachePath string) *Resolver {
	r := &Resolver{
		cachePath: cachePath,
		cache:     map[string]cacheEntry{},
		client:    &http.Client{Timeout: 6 * time.Second},
	}
	r.load()
	r.loadMMDB(filepath.Dir(cachePath))
	return r
}

func (r *Resolver) loadMMDB(dir string) {
	candidates := []string{}
	if p := os.Getenv("GEOIP_MMDB"); p != "" {
		candidates = append(candidates, p)
	}
	candidates = append(candidates,
		filepath.Join(dir, "GeoLite2-City.mmdb"),
		filepath.Join(dir, "GeoLite2-Country.mmdb"),
	)
	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if m, err := OpenMMDB(p); err == nil {
			r.mmdb = m
			r.mmdbType = m.DbType
			return
		}
	}
}

// MMDBInfo 返回离线库状态（供前端提示）。
func (r *Resolver) MMDBInfo() (loaded bool, dbType string) {
	return r.mmdb != nil, r.mmdbType
}

func (r *Resolver) load() {
	data, err := os.ReadFile(r.cachePath)
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &r.cache)
	// 剪枝：清除长期未刷新的过期条目，防止缓存文件无限增长
	cutoff := time.Now().Add(-pruneTTL).Unix()
	pruned := false
	for ip, e := range r.cache {
		if e.FetchedAt < cutoff {
			delete(r.cache, ip)
			pruned = true
		}
	}
	if pruned {
		r.persistLocked()
	}
}

func (r *Resolver) persistLocked() {
	if data, err := json.MarshalIndent(r.cache, "", " "); err == nil {
		_ = os.WriteFile(r.cachePath, data, 0o644)
	}
}

// localResolve 私网/回环/链路本地等地址本地判定，不发起在线查询。
func localResolve(ip string) (Info, bool) {
	p := net.ParseIP(ip)
	if p == nil {
		return Info{}, false
	}
	switch {
	case p.IsLoopback():
		return Info{Country: "本地回环", Code: "loopback"}, true
	case p.IsPrivate():
		return Info{Country: "私有网络", Code: "priv"}, true
	case p.IsLinkLocalUnicast() || p.IsLinkLocalMulticast():
		return Info{Country: "链路本地", Code: "linklocal"}, true
	case p.IsMulticast():
		return Info{Country: "多播地址", Code: "multicast"}, true
	case p.IsUnspecified():
		return Info{Country: "未指定地址", Code: "unspecified"}, true
	}
	return Info{}, false
}

// Lookup 批量解析 IP 归属地：本地私网判定 → 离线 mmdb（若加载）→ 缓存 → 在线批量查询。
// 查询失败的 IP 不写入缓存（Country 为空表示本次未能解析）。
func (r *Resolver) Lookup(ips []string) map[string]Info {
	out := map[string]Info{}
	var unknown []string
	seen := map[string]bool{}

	r.mu.Lock()
	now := time.Now().Unix()
	for _, raw := range ips {
		ip := strings.TrimSpace(raw)
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		if info, ok := localResolve(ip); ok {
			out[ip] = info
			continue
		}
		if r.mmdb != nil {
			// 离线库：完全本地解析，不产生网络请求
			if rec, err := r.mmdb.LookupString(ip); err == nil && rec != nil {
				country, code, lat, lon := CountryInfo(rec)
				out[ip] = Info{Country: country, Code: code, Lat: lat, Lon: lon}
			}
			continue
		}
		if e, ok := r.cache[ip]; ok && now-e.FetchedAt < int64(cacheTTL/time.Second) {
			out[ip] = Info{Country: e.Country, Code: e.Code}
			continue
		}
		if len(unknown) < maxUnknown {
			unknown = append(unknown, ip)
		}
	}
	r.mu.Unlock()

	if len(unknown) == 0 {
		return out
	}

	fetched := map[string]cacheEntry{}
	for i := 0; i < len(unknown); i += batchSize {
		end := i + batchSize
		if end > len(unknown) {
			end = len(unknown)
		}
		batch := unknown[i:end]
		results, err := r.queryBatch(batch)
		if err != nil {
			continue
		}
		for j, ip := range batch {
			if j >= len(results) {
				break
			}
			res := results[j]
			if res.Status != "success" || res.Country == "" {
				continue // 解析失败不缓存，等待下次重试
			}
			out[ip] = Info{Country: res.Country, Code: res.CountryCode}
			fetched[ip] = cacheEntry{Country: res.Country, Code: res.CountryCode, FetchedAt: now}
		}
	}

	if len(fetched) > 0 {
		r.mu.Lock()
		for ip, e := range fetched {
			r.cache[ip] = e
		}
		r.persistLocked()
		r.mu.Unlock()
	}
	return out
}

type batchItem struct {
	Status      string `json:"status"`
	Message     string `json:"message"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
}

func (r *Resolver) queryBatch(ips []string) ([]batchItem, error) {
	body, err := json.Marshal(ips)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("GeoIP 在线查询失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GeoIP 服务返回 HTTP %d (免费额度为 15 请求/分钟，稍后重试)", resp.StatusCode)
	}
	var items []batchItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil, fmt.Errorf("GeoIP 响应解析失败: %w", err)
	}
	return items, nil
}
