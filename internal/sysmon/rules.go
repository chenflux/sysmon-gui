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

// DefaultRuleConfig 内置默认规则集：以通用化后的「快速检测基线 v2」为主体
// （覆盖进程/网络/DNS/文件/注册表/驱动/管道/WMI/ADS 全检测面），
// 另附 2 条 IOC 演示规则示范多条件组的编辑方式。
// 已剥离特定机器/厂商路径，任何环境可安全套用。
func DefaultRuleConfig() *RuleConfig {
	empty := func() []*CondGroup { return []*CondGroup{{Relation: "or"}} }
	return &RuleConfig{
		SchemaVersion:  "4.90",
		HashAlgorithms: "sha256,IMPHASH",
		DnsLookup:      false,
		Rules: []*Rule{
			{ID: "base_proc_exclude", Name: "基线-排除系统噪音进程", EventType: "ProcessCreate", OnMatch: "exclude", Enabled: true,
				Note: "系统常驻服务进程与高频父进程命令行，降噪用",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "Image", Op: "contains any", Values: []string{"svchost.exe", "CompPkgSrv.exe", "taskhostw.exe", "sppsvc.exe", "conhost.exe", "RuntimeBroker.exe", "sihost.exe", "dllhost.exe", "dwm.exe", "fontdrvhost.exe", "WmiPrvSE.exe"}},
					{Field: "ParentCommandLine", Op: "contains any", Values: []string{"SearchIndexer.exe /Embedding", "svchost.exe -k DcomLaunch", "svchost.exe -k InvSvcGroup", "svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc"}},
				}}}},
			{ID: "base_proc_include", Name: "基线-记录全部进程创建", EventType: "ProcessCreate", OnMatch: "include", Enabled: true,
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "Image", Op: "contains", Values: []string{"."}},
				}}}},
			{ID: "base_net_exclude", Name: "基线-排除回环与链路本地网络", EventType: "NetworkConnect", OnMatch: "exclude", Enabled: true,
				Note: "127.0.0.x / ::1 / 0.0.0.0 / fe80: 链路本地",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "DestinationIp", Op: "contains any", Values: []string{"127.0.0.", "0.0.0.0", "::1"}},
					{Field: "DestinationIp", Op: "begin with", Values: []string{"fe80:"}},
				}}}},
			{ID: "base_net_include", Name: "基线-记录全部外联(IPv4+IPv6)", EventType: "NetworkConnect", OnMatch: "include", Enabled: true,
				Note: "含 IPv4(.)与 IPv6(:) 两种格式",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "DestinationIp", Op: "contains any", Values: []string{".", ":"}},
				}}}},
			{ID: "base_procstop_exclude", Name: "基线-排除svchost进程终止", EventType: "ProcessTerminate", OnMatch: "exclude", Enabled: true,
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "Image", Op: "contains", Values: []string{"svchost.exe"}},
				}}}},
			{ID: "base_procstop_include", Name: "基线-记录全部进程终止", EventType: "ProcessTerminate", OnMatch: "include", Enabled: true,
				Note: "无条件规则 = 记录该类型全部事件（未被排除规则命中的）",
				Groups: empty()},
			{ID: "base_rawread_include", Name: "基线-记录全部磁盘原始读取", EventType: "RawAccessRead", OnMatch: "include", Enabled: true,
				Note: "无条件规则；事件量极低且为绕过型攻击特征（卷影复制/物理盘读取）",
				Groups: empty()},
			{ID: "base_imgload_exclude_sys32", Name: "基线-排除System32已签名模块", EventType: "ImageLoad", OnMatch: "exclude", Enabled: true,
				Note: "组内「且」：System32 前缀 且 已签名 才排除——未签名恶意DLL放入系统目录仍会记录",
				Groups: []*CondGroup{{Relation: "and", Conditions: []*Condition{
					{Field: "ImageLoaded", Op: "begin with", Values: []string{"C:\\Windows\\System32\\"}},
					{Field: "Signed", Op: "is", Values: []string{"true"}},
				}}}},
			{ID: "base_imgload_exclude_wow64", Name: "基线-排除SysWOW64已签名模块", EventType: "ImageLoad", OnMatch: "exclude", Enabled: true,
				Groups: []*CondGroup{{Relation: "and", Conditions: []*Condition{
					{Field: "ImageLoaded", Op: "begin with", Values: []string{"C:\\Windows\\SysWOW64\\"}},
					{Field: "Signed", Op: "is", Values: []string{"true"}},
				}}}},
			{ID: "base_imgload_exclude_pf", Name: "基线-排除ProgramFiles已签名模块", EventType: "ImageLoad", OnMatch: "exclude", Enabled: true,
				Groups: []*CondGroup{{Relation: "and", Conditions: []*Condition{
					{Field: "ImageLoaded", Op: "begin with", Values: []string{"C:\\Program Files\\"}},
					{Field: "Signed", Op: "is", Values: []string{"true"}},
				}}}},
			{ID: "base_imgload_include", Name: "基线-记录可疑模块加载", EventType: "ImageLoad", OnMatch: "include", Enabled: true,
				Note: "脚本解释器的模块加载 + 工具特征名 + 非系统目录可执行模块 + 全部未签名模块",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "Image", Op: "is", Values: []string{"C:\\Windows\\System32\\cscript.exe", "C:\\Windows\\System32\\wscript.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"}},
					{Field: "ImageLoaded", Op: "contains any", Values: []string{"mimikatz", "cobaltstrike", "beacon"}},
					{Field: "ImageLoaded", Op: "end with", Values: []string{".exe", ".dll", ".sys"}},
					{Field: "Signed", Op: "is", Values: []string{"false"}},
				}}}},
			{ID: "base_crt_exclude", Name: "基线-排除系统进程远程线程", EventType: "CreateRemoteThread", OnMatch: "exclude", Enabled: true,
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "SourceImage", Op: "contains any", Values: []string{"svchost.exe", "wininit.exe", "csrss.exe", "services.exe", "winlogon.exe", "audiodg.exe", "wbem\\WmiPrvSE.exe"}},
					{Field: "TargetImage", Op: "end with", Values: []string{"Google\\Chrome\\Application\\chrome.exe"}},
				}}}},
			{ID: "base_crt_include", Name: "基线-记录全部远程线程创建", EventType: "CreateRemoteThread", OnMatch: "include", Enabled: true,
				Note: "无条件规则；注入检测核心事件",
				Groups: empty()},
			{ID: "base_access_include", Name: "基线-记录敏感进程访问", EventType: "ProcessAccess", OnMatch: "include", Enabled: true,
				Note: "转储调用栈特征 + 高危访问掩码(0x1010读lsass等) + 可疑目录发起的访问",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "CallTrace", Op: "contains any", Values: []string{"dbghelp.dll", "dbgcore.dll"}},
					{Field: "GrantedAccess", Op: "is", Values: []string{"0x21410", "0x1FFFFF", "0x1F1FFF", "0x1010", "0x143A", "0x0800", "0x0810", "0x0820"}},
					{Field: "SourceImage", Op: "begin with", Values: []string{"C:\\PerfLogs\\", "C:\\$Recycle.bin\\", "C:\\Intel\\Logs\\", "C:\\Users\\Default\\", "C:\\Users\\Public\\", "C:\\Windows\\Fonts\\", "C:\\Windows\\Debug\\", "C:\\Windows\\Media\\", "C:\\Windows\\Temp\\"}},
					{Field: "SourceImage", Op: "contains", Values: []string{"\\Temp\\"}},
				}}}},
			{ID: "base_access_exclude", Name: "基线-排除常规进程访问噪音", EventType: "ProcessAccess", OnMatch: "exclude", Enabled: true,
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "SourceImage", Op: "contains any", Values: []string{"wmiprvse.exe", "GoogleUpdate.exe", "taskmgr.exe", "VBoxService.exe", "vmtoolsd.exe"}},
					{Field: "GrantedAccess", Op: "is", Values: []string{"0x1000", "0x1400", "0x101400", "0x101000"}},
				}}}},
			{ID: "base_driver_include", Name: "基线-记录未签名驱动加载", EventType: "DriverLoad", OnMatch: "include", Enabled: true,
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "Signed", Op: "is", Values: []string{"false"}},
				}}}},
			{ID: "base_file_include", Name: "基线-记录敏感文件创建", EventType: "FileCreate", OnMatch: "include", Enabled: true,
				Note: "可执行/脚本类扩展名 + 下载/启动目录 + 常见落地目录",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "TargetFilename", Op: "end with", Values: []string{".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".lnk", ".scr", ".pif", ".jar", ".py", ".inf", ".reg"}},
					{Field: "TargetFilename", Op: "contains any", Values: []string{"\\Downloads\\", "\\Startup\\"}},
					{Field: "TargetFilename", Op: "begin with", Values: []string{"C:\\Windows\\Temp\\", "C:\\PerfLogs\\", "C:\\Users\\Public\\"}},
				}}}},
			{ID: "base_stream_include", Name: "基线-记录NTFS数据流创建", EventType: "FileCreateStreamHash", OnMatch: "include", Enabled: true,
				Note: "无条件规则；ADS 隐藏载荷/Mark-of-the-Web 检测，事件量低",
				Groups: empty()},
			{ID: "base_reg_include", Name: "基线-记录持久化相关注册表", EventType: "RegistryEvent", OnMatch: "include", Enabled: true,
				Note: "自启动项/Winlogon 劫持/IFEO/服务镜像路径",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "TargetObject", Op: "contains any", Values: []string{"\\CurrentVersion\\Run", "\\Policies\\Explorer\\Run", "Group Policy\\Scripts", "\\CurrentVersion\\Windows\\Load"}},
					{Field: "TargetObject", Op: "begin with", Values: []string{"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\"}},
				}}}},
			{ID: "base_filetime_include", Name: "基线-记录可执行文件时间篡改", EventType: "FileCreateTime", OnMatch: "include", Enabled: true,
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "TargetFilename", Op: "end with", Values: []string{".exe"}},
				}}}},
			{ID: "base_pipe_include", Name: "基线-记录攻击工具命名管道", EventType: "PipeEvent", OnMatch: "include", Enabled: true,
				Note: "PsExec/PaExec/CS/Mimikatz 等远控与凭证工具的管道特征",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "PipeName", Op: "contains any", Values: []string{"psexesvc", "paexec", "remcom", "csexec", "lsadump", "cachedump", "wceservicepipe", "mimikatz", "pcheap_reuse", "gruntsvc", "moze_irc", "interprocess", "namepipe_morewindows"}},
				}}}},
			{ID: "base_wmi_include", Name: "基线-记录全部WMI事件订阅", EventType: "WmiEvent", OnMatch: "include", Enabled: true,
				Note: "无条件规则；WMI 持久化事件量极低且高价值",
				Groups: empty()},
			{ID: "base_dns_exclude", Name: "基线-排除常见DNS白名单", EventType: "DnsQuery", OnMatch: "exclude", Enabled: true,
				Note: "系统更新/常用软件/CDN 的常规解析噪音",
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "QueryName", Op: "end with", Values: []string{".microsoft.com", ".windows.com", ".windowsupdate.com", ".microsoftonline.com", ".msftconnecttest.com", ".msftncsi.com", ".msn.com", ".live.com", ".apple.com", ".icloud.com", ".google.com", ".qq.com", ".taobao.com", ".alipay.com", ".163.com", ".ntp.org", ".arpa", ".xboxlive.com", ".skype.com", ".msedge.net"}},
				}}}},
			{ID: "base_dns_include", Name: "基线-记录其余全部DNS查询", EventType: "DnsQuery", OnMatch: "include", Enabled: true,
				Groups: []*CondGroup{{Relation: "or", Conditions: []*Condition{
					{Field: "QueryName", Op: "contains", Values: []string{"."}},
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
			if r.OnMatch == "include" {
				// Sysmon 语义：空 include = 记录该类型全部事件，合法但需提示
				lint.Warnings = append(lint.Warnings, prefix+": 无条件规则，将记录该类型的全部事件（如非有意为之请补充条件）")
			} else {
				lint.Errors = append(lint.Errors, prefix+": 排除规则已启用但没有有效条件（无条件排除会丢弃全部事件）")
			}
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
