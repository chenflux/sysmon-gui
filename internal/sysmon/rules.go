package sysmon

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type RuleConfig struct {
	SchemaVersion  string  `json:"schema_version"`
	HashAlgorithms string  `json:"hash_algorithms"`
	DnsLookup      bool    `json:"dns_lookup"`
	Rules          []*Rule `json:"rules"`
}

type Rule struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	EventType string       `json:"event_type"`
	OnMatch   string       `json:"on_match"`
	Enabled   bool         `json:"enabled"`
	Note      string       `json:"note"`
	Groups    []*CondGroup `json:"groups"`
}

type CondGroup struct {
	Relation   string       `json:"relation"`
	Conditions []*Condition `json:"conditions"`
}

type Condition struct {
	Field  string   `json:"field"`
	Op     string   `json:"op"`
	Values []string `json:"values"`
}

func DefaultRuleConfig() *RuleConfig {
	return &RuleConfig{
		SchemaVersion:  "4.90",
		HashAlgorithms: "md5,sha1,sha256",
		DnsLookup:      false,
		Rules: []*Rule{
			{ID: "base_proc_exclude", Name: "基线-排除系统噪音进程", EventType: "ProcessCreate", OnMatch: "exclude", Enabled: true,
				Note: "命中系统常驻进程时不记录，降低日志噪音；演示“排除/不包含”用法",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "Image", Op: "contains any", Values: []string{"svchost.exe", "taskhostw.exe", "conhost.exe", "RuntimeBroker.exe", "sihost.exe", "dllhost.exe", "csrss.exe", "wininit.exe", "services.exe", "winlogon.exe", "SearchIndexer.exe", "fontdrvhost.exe", "dwm.exe", "WmiPrvSE.exe"}},
				}}}},
			{ID: "base_proc_include", Name: "基线-记录进程创建", EventType: "ProcessCreate", OnMatch: "include", Enabled: true,
				Note: "记录其余全部进程创建事件",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "Image", Op: "contains", Values: []string{"."}},
				}}}},
			{ID: "base_net_exclude", Name: "基线-排除本地回环网络", EventType: "NetworkConnect", OnMatch: "exclude", Enabled: true,
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "DestinationIp", Op: "contains any", Values: []string{"127.0.0.", "::1", "0.0.0.0"},
					},
				}}}},
			{ID: "base_net_include", Name: "基线-记录网络连接", EventType: "NetworkConnect", OnMatch: "include", Enabled: true,
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "DestinationIp", Op: "contains", Values: []string{"."},
					},
				}}}},
			{ID: "base_dns_exclude", Name: "基线-排除常见DNS噪音", EventType: "DnsQuery", OnMatch: "exclude", Enabled: true,
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "QueryName", Op: "contains any", Values: []string{".microsoft.com", ".windows.com", ".msftconnecttest.com", ".msftncsi.com"},
					},
				}}}},
			{ID: "base_dns_include", Name: "基线-记录DNS查询", EventType: "DnsQuery", OnMatch: "include", Enabled: true,
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "QueryName", Op: "contains", Values: []string{"."},
					},
				}}}},
			{ID: "base_file_include", Name: "基线-记录敏感文件创建", EventType: "FileCreate", OnMatch: "include", Enabled: true,
				Note: "仅记录可执行/脚本类文件创建",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "TargetFilename", Op: "end with", Values: []string{".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".lnk", ".scr", ".pif", ".jar"}},
				}}}},
			{ID: "base_imgload", Name: "基线-记录未签名模块加载(默认停用)", EventType: "ImageLoad", OnMatch: "include", Enabled: false,
				Note: "事件量极大，默认停用，需要时手动启用",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "Signed", Op: "is", Values: []string{"false"}},
				}}}},
			{ID: "ioc_creddump_demo", Name: "IOC示例-凭证转储工具检测", EventType: "ProcessCreate", OnMatch: "include", Enabled: true,
				Note: "演示复杂逻辑：组1(与) 可疑命令行+解释器进程；组2(或) 直接运行攻击工具。多个条件组之间为“或”关系",
				Groups: []*CondGroup{
					{Relation: "and", Conditions: []*Condition{
						{Field: "CommandLine", Op: "contains any", Values: []string{"mimikatz", "sekurlsa", "logonpasswords", "lsadump", "procdump -ma"}},
						{Field: "Image", Op: "end with", Values: []string{"powershell.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe"}},
					}},
					{Relation: "or", Conditions: []*Condition{
						{Field: "Image", Op: "contains any", Values: []string{"mimikatz.exe", "pwdump", "quarks-pwdump"},
						},
					}},
				}},
			{ID: "ioc_domain_demo", Name: "IOC示例-可疑域名检测", EventType: "DnsQuery", OnMatch: "include", Enabled: true,
				Note: "演示“与 + 不包含”组合：可疑域名 且 非浏览器进程发起",
				Groups: []*CondGroup{{Relation: "and", Conditions: []*Condition{
					{Field: "QueryName", Op: "contains any", Values: []string{"example-c2.com", "update-cdn.xyz"},
					},
					{Field: "Image", Op: "excludes any", Values: []string{"chrome.exe", "msedge.exe"}},
				}}}},
		},
	}
}

func LoadRules(path string) (*RuleConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultRuleConfig(), nil
		}
		return nil, err
	}
	var cfg RuleConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("规则文件解析失败: %w", err)
	}
	if len(cfg.Rules) == 0 {
		return DefaultRuleConfig(), nil
	}
	return &cfg, nil
}

func SaveRules(path string, cfg *RuleConfig) error {
	if cfg.SchemaVersion == "" {
		cfg.SchemaVersion = "4.90"
	}
	if cfg.HashAlgorithms == "" {
		cfg.HashAlgorithms = "md5,sha1,sha256"
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

type LintResult struct {
	Errors   []string `json:"errors"`
	Warnings []string `json:"warnings"`
}

func LintRules(cfg *RuleConfig, schema *SchemaInfo) *LintResult {
	lint := &LintResult{}
	if cfg == nil {
		lint.Errors = append(lint.Errors, "规则配置为空")
		return lint
	}
	if schema == nil {
		schema = fallbackSchema()
	}
	knownOps := schema.Ops
	names := map[string]int{}
	for i, r := range cfg.Rules {
		prefix := fmt.Sprintf("规则 #%d", i+1)
		if r.Name != "" {
			prefix = fmt.Sprintf("规则[%s]", r.Name)
		}
		if strings.TrimSpace(r.Name) == "" {
			lint.Errors = append(lint.Errors, fmt.Sprintf("%s: 名称不能为空", prefix))
		} else {
			names[r.Name]++
		}
		schemaFields, typeKnown := schema.Fields[r.EventType]
		if !typeKnown {
			lint.Errors = append(lint.Errors, fmt.Sprintf("%s: 未知事件类型 %q", prefix, r.EventType))
		}
		if r.OnMatch != "include" && r.OnMatch != "exclude" {
			lint.Errors = append(lint.Errors, fmt.Sprintf("%s: 匹配方式必须为 include 或 exclude", prefix))
		}
		validConds := 0
		for gi, g := range r.Groups {
			if g.Relation != "and" && g.Relation != "or" {
				lint.Errors = append(lint.Errors, fmt.Sprintf("%s 组#%d: 逻辑关系必须为 and 或 or", prefix, gi+1))
			}
			for ci, c := range g.Conditions {
				condPrefix := fmt.Sprintf("%s 组#%d 条件#%d", prefix, gi+1, ci+1)
				if strings.TrimSpace(c.Field) == "" {
					lint.Errors = append(lint.Errors, condPrefix+": 字段不能为空")
					continue
				}
				if !knownOps[c.Op] {
					lint.Errors = append(lint.Errors, fmt.Sprintf("%s: 未知操作符 %q", condPrefix, c.Op))
					continue
				}
				if len(c.Values) == 0 {
					lint.Errors = append(lint.Errors, condPrefix+": 至少需要一个 IOC 值")
					continue
				}
				for vi, v := range c.Values {
					if strings.TrimSpace(v) == "" {
						lint.Errors = append(lint.Errors, fmt.Sprintf("%s 值#%d: 值不能为空", condPrefix, vi+1))
					}
					if strings.Contains(v, ";") {
						lint.Errors = append(lint.Errors, fmt.Sprintf("%s 值#%d: 值中不能包含分号 (;)", condPrefix, vi+1))
					}
				}
				if typeKnown && !containsStr(schemaFields, c.Field) {
					hint := strings.Join(schemaFields, ", ")
					if len(hint) > 160 {
						hint = hint[:160] + "…"
					}
					lint.Errors = append(lint.Errors, fmt.Sprintf("%s: 字段 %q 不是事件 %s 的有效字段 (依据 Sysmon 官方 schema)。有效字段: %s", condPrefix, c.Field, r.EventType, hint))
				}
				validConds++
			}
		}
		if r.Enabled && validConds == 0 {
			lint.Errors = append(lint.Errors, prefix+": 规则已启用但没有有效条件")
		}
	}
	for n, c := range names {
		if c > 1 {
			lint.Warnings = append(lint.Warnings, fmt.Sprintf("存在 %d 个同名规则「%s」，建议区分命名", c, n))
		}
	}
	return lint
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func ValidateConfig(cfg *RuleConfig, schema *SchemaInfo) error {
	lint := LintRules(cfg, schema)
	if len(lint.Errors) > 0 {
		return fmt.Errorf("%s", strings.Join(lint.Errors, "；"))
	}
	return nil
}

var ruleIDSeq int64

func NewRuleID() string {
	seq := atomic.AddInt64(&ruleIDSeq, 1)
	return fmt.Sprintf("r_%d_%d", time.Now().UnixNano(), seq)
}
