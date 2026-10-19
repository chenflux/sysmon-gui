package sysmon

type EventTypeInfo struct {
	Type    string   `json:"type"`
	Label   string   `json:"label"`
	EventID int      `json:"event_id"`
	Fields  []string `json:"fields"`
}

type OperatorInfo struct {
	Op    string `json:"op"`
	Label string `json:"label"`
	Multi bool   `json:"multi"`
}

var eventFields = map[string][]string{
	"ProcessCreate":        {"Image", "CommandLine", "ParentImage", "ParentCommandLine", "OriginalFileName", "CurrentDirectory", "User", "IntegrityLevel", "Hashes", "ProcessId", "ParentProcessId"},
	"FileCreateTime":       {"TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime", "Image"},
	"NetworkConnect":       {"Image", "DestinationIp", "DestinationHostname", "DestinationPort", "SourceIp", "SourcePort", "Protocol", "Initiated", "User", "ProcessId"},
	"ProcessTerminate":     {"Image", "ProcessId", "User", "ExitStatus"},
	"DriverLoad":           {"ImageLoaded", "Signature", "SignatureStatus", "Signed", "Hashes", "User"},
	"ImageLoad":            {"ImageLoaded", "Image", "Signed", "Signature", "SignatureStatus", "Hashes", "User"},
	"CreateRemoteThread":   {"SourceImage", "TargetImage", "NewThreadId", "StartAddress", "StartModule", "StartFunction", "SourceProcessId", "TargetProcessId"},
	"RawAccessRead":        {"Image", "Device", "ProcessId"},
	"ProcessAccess":        {"SourceImage", "TargetImage", "GrantedAccess", "CallTrace", "SourceProcessId", "TargetProcessId", "SourceUser", "TargetUser"},
	"FileCreate":           {"TargetFilename", "Image", "CreationUtcTime", "User", "ProcessId"},
	"RegistryEvent":        {"TargetObject", "NewName", "Details", "Image", "EventType", "User", "ProcessId"},
	"FileCreateStreamHash": {"TargetFilename", "Image", "Hashes", "User"},
	"PipeEvent":            {"PipeName", "Image", "EventType", "ProcessId"},
	"WmiEvent":             {"EventType", "Operation", "User", "Name", "Type", "Destination", "Consumer", "Filter", "Query"},
	"DnsQuery":             {"QueryName", "QueryStatus", "Image", "ProcessId", "QueryResults"},
	"FileDelete":           {"TargetFilename", "Image", "Hashes", "IsExecutable", "User", "Archived"},
	"ProcessTampering":     {"Image", "OriginalFileName", "ProcessId", "Hashes"},
	"FileDeleteDetected":   {"TargetFilename", "Image", "User", "Hashes"},
	"ClipboardChange":      {"ClientInfo", "Hashes", "Session", "Image"},
	"FileBlockExecutable":  {"Hashes", "Archived", "IsExecutable", "User", "Image", "TargetFilename"},
	"FileBlockShredding":   {"TargetFilename", "Image", "User", "Session"},
	"FileExecutableDetected": {"Hashes", "User", "Image", "TargetFilename"},
}

var eventMeta = []struct {
	Type  string
	Label string
	ID    int
}{
	{"ProcessCreate", "进程创建", 1},
	{"FileCreateTime", "文件创建时间更改", 2},
	{"NetworkConnect", "网络连接", 3},
	{"ProcessTerminate", "进程终止", 5},
	{"DriverLoad", "驱动加载", 6},
	{"ImageLoad", "镜像加载", 7},
	{"CreateRemoteThread", "创建远程线程", 8},
	{"RawAccessRead", "原始磁盘读取", 9},
	{"ProcessAccess", "进程访问", 10},
	{"FileCreate", "文件创建", 11},
	{"RegistryEvent", "注册表事件", 12},
	{"FileCreateStreamHash", "文件流创建", 15},
	{"PipeEvent", "管道事件", 17},
	{"WmiEvent", "WMI事件", 19},
	{"DnsQuery", "DNS查询", 22},
	{"FileDelete", "文件删除(归档)", 23},
	{"ProcessTampering", "进程篡改", 25},
	{"FileDeleteDetected", "文件删除检测", 26},
	{"ClipboardChange", "剪贴板变更", 24},
	{"FileBlockExecutable", "阻止可执行文件", 27},
	{"FileBlockShredding", "阻止文件粉碎", 28},
	{"FileExecutableDetected", "可执行文件检测", 29},
}

func EventTypes() []EventTypeInfo {
	out := make([]EventTypeInfo, 0, len(eventMeta))
	for _, m := range eventMeta {
		fields, ok := eventFields[m.Type]
		if !ok {
			fields = []string{"Image", "User"}
		}
		out = append(out, EventTypeInfo{Type: m.Type, Label: m.Label, EventID: m.ID, Fields: fields})
	}
	return out
}

var operators = []OperatorInfo{
	{Op: "is", Label: "等于"},
	{Op: "is not", Label: "不等于"},
	{Op: "contains", Label: "包含"},
	{Op: "contains any", Label: "包含任一 (多值)", Multi: true},
	{Op: "contains all", Label: "同时包含 (多值)", Multi: true},
	{Op: "excludes", Label: "不包含"},
	{Op: "excludes any", Label: "不包含任一 (多值)", Multi: true},
	{Op: "begin with", Label: "以…开头"},
	{Op: "not begin with", Label: "不以…开头"},
	{Op: "end with", Label: "以…结尾"},
	{Op: "not end with", Label: "不以…结尾"},
	{Op: "image", Label: "文件名匹配"},
	{Op: "lower than", Label: "小于 (数值)"},
	{Op: "higher than", Label: "大于 (数值)"},
}

func Operators() []OperatorInfo {
	out := make([]OperatorInfo, len(operators))
	copy(out, operators)
	return out
}

func KnownEventTypes() map[string]bool {
	m := map[string]bool{}
	for _, e := range eventMeta {
		m[e.Type] = true
	}
	return m
}

func KnownOperators() map[string]bool {
	m := map[string]bool{}
	for _, o := range operators {
		m[o.Op] = true
	}
	return m
}

var EIDNames = map[int]string{
	1:   "进程创建",
	2:   "文件创建时间更改",
	3:   "网络连接",
	4:   "Sysmon状态变更",
	5:   "进程终止",
	6:   "驱动加载",
	7:   "镜像加载",
	8:   "创建远程线程",
	9:   "原始磁盘读取",
	10:  "进程访问",
	11:  "文件创建",
	12:  "注册表创建/删除",
	13:  "注册表值设置",
	14:  "注册表重命名",
	15:  "文件流创建",
	16:  "Sysmon配置变更",
	17:  "管道创建",
	18:  "管道连接",
	19:  "WMI过滤器",
	20:  "WMI消费者",
	21:  "WMI绑定",
	22:  "DNS查询",
	23:  "文件删除归档",
	24:  "剪贴板变更",
	25:  "进程篡改",
	26:  "文件删除检测",
	27:  "阻止可执行文件",
	28:  "阻止文件粉碎",
	29:  "可执行文件检测",
	255: "错误",
}

func EIDName(id int) string {
	if n, ok := EIDNames[id]; ok {
		return n
	}
	return "未知事件"
}
