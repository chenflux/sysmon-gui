package events

import (
	"fmt"
	"sort"
	"strings"
)

// TreeEvent 挂在进程节点时间线上的单条关联事件（EID 1 之外的全部类型）。
type TreeEvent struct {
	RecordID int64 `json:"record_id"`
	EventID  int   `json:"event_id"`
	Time     string `json:"time"`
	Data     []KV  `json:"data,omitempty"`
}

// ProcessNode 进程谱系树节点：EID 1 自关联成树，其余事件按 ProcessGuid 挂载。
type ProcessNode struct {
	GUID            string         `json:"guid"`
	ProcessID       string         `json:"process_id"`
	Image           string         `json:"image"`
	CommandLine     string         `json:"command_line,omitempty"`
	User            string         `json:"user,omitempty"`
	StartTime       string         `json:"start_time,omitempty"`
	ParentGUID      string         `json:"parent_guid,omitempty"`
	ParentProcessID string         `json:"parent_process_id,omitempty"`
	ParentImage     string         `json:"parent_image,omitempty"`
	RecordID        int64          `json:"record_id,omitempty"`
	Synthetic       bool           `json:"synthetic,omitempty"` // 窗口内无 EID 1（父链缺失或启动在窗口外）
	Children        []*ProcessNode `json:"children,omitempty"`
	Events          []TreeEvent    `json:"events,omitempty"`
	EventCount      int            `json:"event_count"`
	EventsTruncated bool           `json:"events_truncated,omitempty"`
}

// TreeResult 谱系查询结果：以最顶层可达祖先为根的链式树 + 焦点进程完整子树。
type TreeResult struct {
	Root      *ProcessNode `json:"root"`
	FocusGUID string       `json:"focus_guid"`
	FocusPID  string       `json:"focus_pid"`
	Fetch     int          `json:"fetch"`
	Scanned   int          `json:"scanned"`
	Truncated bool         `json:"truncated"` // 已触及加载条数上限，窗口外信息缺失
}

const maxNodeEvents = 200

func dataVal(ev Event, name string) string {
	for _, kv := range ev.Data {
		if kv.Name == name {
			return kv.Value
		}
	}
	return ""
}

// ProcessTree 依据一个事件窗口构建指定 ProcessGuid 的进程谱系。
// 祖先链上的节点只保留通向焦点进程的子分支；焦点进程则保留全部后代子树。
func ProcessTree(guid string, fetch int, hours int) (*TreeResult, error) {
	guid = strings.TrimSpace(guid)
	if guid == "" {
		return nil, fmt.Errorf("缺少 guid 参数")
	}
	if fetch <= 0 {
		fetch = 5000
	}
	if fetch > MaxFetch {
		fetch = MaxFetch
	}

	evs, err := fetchWindow(Options{Fetch: fetch, Hours: hours})
	if err != nil {
		return nil, err
	}
	return buildProcessTree(evs, guid, fetch)
}

func buildProcessTree(evs []Event, guid string, fetch int) (*TreeResult, error) {

	nodes := map[string]*ProcessNode{}
	var getOrCreate func(g string) *ProcessNode
	getOrCreate = func(g string) *ProcessNode {
		if n, ok := nodes[g]; ok {
			return n
		}
		n := &ProcessNode{GUID: g, Synthetic: true}
		nodes[g] = n
		return n
	}

	for _, ev := range evs {
		if ev.EventID == 1 {
			pg := dataVal(ev, "ProcessGuid")
			if pg == "" {
				continue
			}
			n := getOrCreate(pg)
			n.ProcessID = dataVal(ev, "ProcessId")
			n.Image = dataVal(ev, "Image")
			n.CommandLine = dataVal(ev, "CommandLine")
			n.User = dataVal(ev, "User")
			n.StartTime = ev.Time
			n.ParentGUID = dataVal(ev, "ParentProcessGuid")
			n.ParentProcessID = dataVal(ev, "ParentProcessId")
			n.ParentImage = dataVal(ev, "ParentImage")
			n.RecordID = ev.RecordID
			n.Synthetic = false
			continue
		}
		pg := dataVal(ev, "ProcessGuid")
		if pg == "" {
			pg = dataVal(ev, "SourceProcessGuid") // EID 8/10 等以源进程为主线挂载
		}
		if pg == "" {
			continue
		}
		n := getOrCreate(pg)
		if n.Synthetic {
			// 窗口外启动的进程：从关联事件补全基本信息
			if n.ProcessID == "" {
				n.ProcessID = dataVal(ev, "ProcessId")
				if n.ProcessID == "" {
					n.ProcessID = dataVal(ev, "SourceProcessId")
				}
			}
			if n.Image == "" {
				n.Image = dataVal(ev, "Image")
				if n.Image == "" {
					n.Image = dataVal(ev, "SourceImage")
				}
			}
			if n.User == "" {
				n.User = dataVal(ev, "User")
				if n.User == "" {
					n.User = dataVal(ev, "SourceUser")
				}
			}
		}
		n.EventCount++
		if len(n.Events) < maxNodeEvents {
			n.Events = append(n.Events, TreeEvent{RecordID: ev.RecordID, EventID: ev.EventID, Time: ev.Time, Data: ev.Data})
		} else {
			n.EventsTruncated = true
		}
	}

	focus, ok := nodes[guid]
	if !ok {
		return nil, fmt.Errorf("当前窗口内未找到该进程的任何事件 (GUID: %s)，可尝试增大「加载条数」后重试", guid)
	}

	// 链接父子关系（父节点须在窗口内）
	childOf := map[string][]*ProcessNode{}
	for _, n := range nodes {
		if n.ParentGUID != "" && n.ParentGUID != n.GUID {
			if _, exists := nodes[n.ParentGUID]; exists {
				childOf[n.ParentGUID] = append(childOf[n.ParentGUID], n)
			}
		}
	}
	for p, kids := range childOf {
		nodes[p].Children = kids
		sort.SliceStable(nodes[p].Children, func(i, j int) bool {
			return nodes[p].Children[i].StartTime < nodes[p].Children[j].StartTime
		})
	}
	for _, n := range nodes {
		sort.SliceStable(n.Events, func(i, j int) bool { return n.Events[i].Time < n.Events[j].Time })
	}

	// 自焦点向上求祖先链（防环）
	chain := []*ProcessNode{focus}
	seen := map[string]bool{focus.GUID: true}
	cur := focus
	for cur.ParentGUID != "" && cur.ParentGUID != cur.GUID {
		p, exists := nodes[cur.ParentGUID]
		if !exists || seen[p.GUID] {
			break
		}
		seen[p.GUID] = true
		chain = append([]*ProcessNode{p}, chain...)
		cur = p
	}

	// 祖先链上的节点仅保留通向焦点的子分支，避免展示大量无关兄弟进程
	for i := 0; i < len(chain)-1; i++ {
		next := chain[i+1]
		kept := chain[i].Children[:0]
		for _, c := range chain[i].Children {
			if c == next {
				kept = append(kept, c)
			}
		}
		chain[i].Children = kept
	}

	return &TreeResult{
		Root:      chain[0],
		FocusGUID: focus.GUID,
		FocusPID:  focus.ProcessID,
		Fetch:     fetch,
		Scanned:   len(evs),
		Truncated: len(evs) >= fetch,
	}, nil
}
