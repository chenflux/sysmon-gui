package events

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"sysmon-gui/internal/evtapi"
	"sysmon-gui/internal/sysmon"
)

const Channel = "Microsoft-Windows-Sysmon/Operational"

// MaxFetch 单次扫描的事件条数绝对上限（原生 API 支持全量日志）。
const MaxFetch = 100000

type KV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Event struct {
	RecordID int64  `json:"record_id"`
	Time     string `json:"time"`
	EventID  int    `json:"event_id"`
	Level    string `json:"level"`
	Computer string `json:"computer"`
	Data     []KV   `json:"data"`
}

type Options struct {
	EventID       int
	Keyword       string
	Hours         int
	Fetch         int
	Page          int
	PageSize      int
	SinceRecordID int64  // 仅返回 EventRecordID 大于该值的事件（增量刷新）
	ProcGuid      string // 精确匹配 EventData 的 ProcessGuid（进程谱系用）
	ParentGuid    string // 精确匹配 EventData 的 ParentProcessGuid（进程谱系用）
}

type Result struct {
	Total    int     `json:"total"`
	Page     int     `json:"page"`
	PageSize int     `json:"page_size"`
	Events   []Event `json:"events"`
}

type eventXML struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID       int    `xml:"EventID"`
		Level         int    `xml:"Level"`
		Computer      string `xml:"Computer"`
		EventRecordID int64  `xml:"EventRecordID"`
		TimeCreated   struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []struct {
			Name  string `xml:"Name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Data"`
	} `xml:"EventData"`
}

var levelNames = map[int]string{0: "信息", 1: "严重", 2: "错误", 3: "警告", 4: "信息", 5: "详细"}

func buildXPath(o Options) string {
	var sysConds, dataConds []string
	if o.EventID > 0 {
		sysConds = append(sysConds, fmt.Sprintf("(EventID=%d)", o.EventID))
	}
	if o.Hours > 0 {
		sysConds = append(sysConds, fmt.Sprintf("TimeCreated[timediff(@SystemTime) <= %d]", o.Hours*3600000))
	}
	if o.SinceRecordID > 0 {
		sysConds = append(sysConds, fmt.Sprintf("(EventRecordID > %d)", o.SinceRecordID))
	}
	if o.ProcGuid != "" {
		// 注意：谓词值中的大括号会导致事件引擎 XPath 语法错误（15001/38），须去除；
		// 值比较对大括号宽容（裸 GUID 可命中带大括号存储的值）
		dataConds = append(dataConds, fmt.Sprintf("EventData[Data[@Name='ProcessGuid']='%s']", strings.Trim(o.ProcGuid, "{}")))
	}
	if o.ParentGuid != "" {
		dataConds = append(dataConds, fmt.Sprintf("EventData[Data[@Name='ParentProcessGuid']='%s']", strings.Trim(o.ParentGuid, "{}")))
	}
	var parts []string
	if len(sysConds) > 0 {
		parts = append(parts, "System["+strings.Join(sysConds, " and ")+"]")
	}
	if len(dataConds) > 0 {
		parts = append(parts, strings.Join(dataConds, " and "))
	}
	if len(parts) == 0 {
		return ""
	}
	return "*[" + strings.Join(parts, " and ") + "]"
}

func Query(opts Options) (*Result, error) {
	page := opts.Page
	if page <= 0 {
		page = 1
	}
	pageSize := opts.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > MaxFetch {
		pageSize = MaxFetch
	}

	filtered, err := fetchWindow(opts)
	if err != nil {
		return nil, err
	}
	total := len(filtered)

	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	return &Result{
		Total:    total,
		Page:     page,
		PageSize: pageSize,
		Events:   filtered[start:end],
	}, nil
}

func normalizeFetch(f int) int {
	if f <= 0 {
		return 1000
	}
	if f > MaxFetch {
		return MaxFetch
	}
	return f
}

// fetchWindow 拉取一个事件窗口（受 MaxFetch 上限约束），并应用关键字过滤，不做分页。
// 优先使用原生 wevtapi（全量、无子进程），失败时回退 wevtutil。
func fetchWindow(opts Options) ([]Event, error) {
	fetch := normalizeFetch(opts.Fetch)
	if evtapi.Available() {
		evs, err := fetchNative(opts, fetch)
		if err == nil {
			return filterEvents(evs, opts), nil
		}
		msg := err.Error()
		if strings.Contains(msg, "未找到事件日志通道") || strings.Contains(msg, "被拒绝") {
			return nil, err // 与 wevtutil 结果相同，直接返回友好错误
		}
		// 其他错误（如个别渲染失败）回退 wevtutil
	}
	return fetchWevtutil(opts, fetch)
}

func fetchNative(opts Options, fetch int) ([]Event, error) {
	evs := make([]Event, 0, 1024)
	err := evtapi.EachEvent(Channel, buildXPath(opts), fetch, func(xmlText string) error {
		if ev, ok := parseOneXML(xmlText); ok {
			evs = append(evs, ev)
			cacheEventXML(ev.RecordID, xmlText)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return evs, nil
}

func fetchWevtutil(opts Options, fetch int) ([]Event, error) {
	args := []string{"qe", Channel, "/c:" + strconv.Itoa(fetch), "/rd:true", "/f:XML"}
	if q := buildXPath(opts); q != "" {
		args = append(args, "/q:"+q)
	}
	cmd := exec.Command("wevtutil", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	stdout, stderrText, err := sysmon.RunCmdWithTimeout(cmd, 60*time.Second)
	if err != nil {
		errText := strings.TrimSpace(stderrText + " " + err.Error())
		low := strings.ToLower(errText)
		if strings.Contains(low, "超时") || strings.Contains(low, "timeout") {
			return nil, fmt.Errorf("wevtutil 查询超时 (60s)，日志通道可能被占用或损坏")
		}
		if strings.Contains(low, "not found") || strings.Contains(errText, "找不到") || strings.Contains(low, "cannot find") {
			return nil, fmt.Errorf("未找到 Sysmon 日志通道 (%s)，请先安装 Sysmon", Channel)
		}
		if strings.Contains(low, "access") || strings.Contains(errText, "拒绝") {
			return nil, fmt.Errorf("读取事件日志被拒绝: %s", strings.TrimSpace(stderrText))
		}
		return nil, fmt.Errorf("wevtutil 查询失败: %s", errText)
	}

	all := parseXML([]byte(stdout))
	return filterEvents(all, opts), nil
}

func eventFromXML(xe eventXML) Event {
	ev := Event{
		RecordID: xe.System.EventRecordID,
		EventID:  xe.System.EventID,
		Computer: xe.System.Computer,
	}
	if name, ok := levelNames[xe.System.Level]; ok {
		ev.Level = name
	} else {
		ev.Level = "信息"
	}
	ts := xe.System.TimeCreated.SystemTime
	if t, err := time.Parse("2006-01-02T15:04:05.9999999Z0700", ts); err == nil {
		ev.Time = t.UTC().Format("2006-01-02T15:04:05.000Z")
	} else {
		ev.Time = ts
	}
	for _, d := range xe.EventData.Data {
		ev.Data = append(ev.Data, KV{Name: d.Name, Value: strings.TrimSpace(d.Value)})
	}
	return ev
}

// parseOneXML 解析单条事件 XML 文档（EvtRender 输出）。
func parseOneXML(doc string) (Event, bool) {
	var xe eventXML
	if err := xml.Unmarshal([]byte(doc), &xe); err != nil {
		return Event{}, false
	}
	return eventFromXML(xe), true
}

func parseXML(data []byte) []Event {
	var events []Event
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		var xe eventXML
		if err := dec.Decode(&xe); err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		events = append(events, eventFromXML(xe))
	}
	return events
}

/* ---- 原始 XML LRU 缓存（供详情页「查看 XML」） ---- */

const xmlCacheCap = 10000

var (
	xmlMu    sync.Mutex
	xmlMap   = map[int64]string{}
	xmlOrder = make([]int64, 0, xmlCacheCap)
)

func cacheEventXML(id int64, s string) {
	if id == 0 {
		return
	}
	xmlMu.Lock()
	defer xmlMu.Unlock()
	if _, ok := xmlMap[id]; ok {
		xmlMap[id] = s
		return
	}
	// 到达顺序为「最新在前」，因此队尾是最旧事件；淘汰队尾以保留最新的窗口供详情查看
	for len(xmlOrder) >= xmlCacheCap {
		oldest := xmlOrder[len(xmlOrder)-1]
		xmlOrder = xmlOrder[:len(xmlOrder)-1]
		delete(xmlMap, oldest)
	}
	xmlMap[id] = s
	xmlOrder = append(xmlOrder, id)
}

// GetEventXML 返回缓存中的原始事件 XML（仅原生 API 拉取过的事件存在）。
func GetEventXML(id int64) (string, bool) {
	xmlMu.Lock()
	defer xmlMu.Unlock()
	s, ok := xmlMap[id]
	return s, ok
}

func filterEvents(events []Event, opts Options) []Event {
	kw := strings.ToLower(strings.TrimSpace(opts.Keyword))
	if kw == "" {
		return events
	}
	// 支持 "a|b|c" 多值：任一命中即保留（供检测剧本组合筛选）
	terms := []string{}
	for _, t := range strings.Split(kw, "|") {
		if t = strings.TrimSpace(t); t != "" {
			terms = append(terms, t)
		}
	}
	if len(terms) == 0 {
		return events
	}
	out := make([]Event, 0, len(events))
	for _, ev := range events {
		for _, t := range terms {
			if matchKeyword(ev, strings.TrimSpace(t)) {
				out = append(out, ev)
				break
			}
		}
	}
	return out
}

func matchKeyword(ev Event, kw string) bool {
	if strings.Contains(strconv.Itoa(ev.EventID), kw) {
		return true
	}
	if strings.Contains(strings.ToLower(sysmon.EIDName(ev.EventID)), kw) {
		return true
	}
	for _, kv := range ev.Data {
		if strings.Contains(strings.ToLower(kv.Name), kw) || strings.Contains(strings.ToLower(kv.Value), kw) {
			return true
		}
	}
	return false
}

func ToCSV(events []Event) []byte {
	var b bytes.Buffer
	b.WriteString("\xEF\xBB\xBF")
	b.WriteString("时间,事件ID,事件类型,计算机,详情\r\n")
	for _, ev := range events {
		parts := make([]string, 0, len(ev.Data))
		for _, kv := range ev.Data {
			parts = append(parts, kv.Name+"="+kv.Value)
		}
		detail := strings.Join(parts, " | ")
		detail = strings.ReplaceAll(detail, "\"", "'")
		b.WriteString(fmt.Sprintf("%s,%d,%s,%s,\"%s\"\r\n", ev.Time, ev.EventID, sysmon.EIDName(ev.EventID), ev.Computer, detail))
	}
	return b.Bytes()
}
