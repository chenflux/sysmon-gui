package events

import (
	"fmt"
	"testing"
)

func mkXML(evts []Event) string {
	out := ""
	for _, ev := range evts {
		out += "<Event><System><EventID>" + fmt.Sprint(ev.EventID) + "</EventID><Level>4</Level><Computer>PC</Computer><EventRecordID>" + fmt.Sprint(ev.RecordID) + "</EventRecordID><TimeCreated SystemTime=\"" + ev.Time + "\"/></System><EventData>"
		for _, kv := range ev.Data {
			out += "<Data Name=\"" + kv.Name + "\">" + kv.Value + "</Data>"
		}
		out += "</EventData></Event>"
	}
	return out
}

func ev(recordID int, eid int, time string, kvs map[string]string) Event {
	e := Event{RecordID: int64(recordID), EventID: eid, Time: time, Level: "信息", Computer: "PC"}
	for k, v := range kvs {
		e.Data = append(e.Data, KV{Name: k, Value: v})
	}
	return e
}

func TestProcessTreeChainAndEvents(t *testing.T) {
	iso := func(s string) string { return "2026-10-18T" + s + ".000+00:00" }
	// explorer(无父) → winword → powershell(焦点)；另有与 winword 无关的兄弟进程 chrome
	xml := mkXML([]Event{
		ev(1, 1, iso("14:00:00"), map[string]string{
			"ProcessGuid": "{EXPLORER}", "ProcessId": "100", "Image": `C:\Windows\explorer.exe`,
			"CommandLine": `C:\Windows\explorer.exe`, "User": "PC\\u1", "ParentProcessGuid": "{SESSION}",
		}),
		ev(2, 1, iso("14:22:03"), map[string]string{
			"ProcessGuid": "{WINWORD}", "ProcessId": "4012", "Image": `C:\Program Files\winword.exe`,
			"CommandLine": `winword.exe /doc`, "User": "PC\\u1", "ParentProcessGuid": "{EXPLORER}", "ParentProcessId": "100",
			"ParentImage": `C:\Windows\explorer.exe`,
		}),
		ev(3, 1, iso("14:22:05"), map[string]string{
			"ProcessGuid": "{PS}", "ProcessId": "5077", "Image": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			"CommandLine": "powershell.exe -enc JAB...", "User": "PC\\u1", "ParentProcessGuid": "{WINWORD}", "ParentProcessId": "4012",
			"ParentImage": `C:\Program Files\winword.exe`,
		}),
		ev(4, 11, iso("14:22:06"), map[string]string{"ProcessGuid": "{PS}", "Image": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "TargetFilename": `C:\Temp\bad.ps1`}),
		ev(5, 3, iso("14:22:07"), map[string]string{"ProcessGuid": "{PS}", "Image": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "DestinationIp": "45.33.1.1", "DestinationPort": "443"}),
		ev(6, 1, iso("14:30:00"), map[string]string{
			"ProcessGuid": "{CHROME}", "ProcessId": "9999", "Image": `C:\chrome.exe`,
			"ParentProcessGuid": "{EXPLORER}",
		}),
	})
	evs := parseXML([]byte(xml))
	if len(evs) != 6 {
		t.Fatalf("解析事件数 = %d, 期望 6", len(evs))
	}

	res, err := buildProcessTree(evs, "{PS}", 5000)
	if err != nil {
		t.Fatalf("ProcessTree: %v", err)
	}
	if res.Root.GUID != "{EXPLORER}" {
		t.Fatalf("根节点 = %s, 期望 {EXPLORER}（最顶层可达祖先）", res.Root.GUID)
	}
	// 祖先链剪枝：explorer 只保留 winword 分支，不含 chrome
	if len(res.Root.Children) != 1 || res.Root.Children[0].GUID != "{WINWORD}" {
		t.Fatalf("祖先链未剪枝: children=%v", res.Root.Children)
	}
	word := res.Root.Children[0]
	if len(word.Children) != 1 || word.Children[0].GUID != "{PS}" {
		t.Fatalf("winword 子节点错误")
	}
	ps := word.Children[0]
	if ps.EventCount != 2 || len(ps.Events) != 2 {
		t.Fatalf("焦点进程事件数 = %d/%d, 期望 2/2", ps.EventCount, len(ps.Events))
	}
	if ps.Events[0].EventID != 11 || ps.Events[1].EventID != 3 {
		t.Fatalf("事件时间线未按时间排序")
	}
	if res.FocusGUID != "{PS}" || res.FocusPID != "5077" {
		t.Fatalf("焦点信息错误: %v %v", res.FocusGUID, res.FocusPID)
	}
}

func TestProcessTreeSyntheticNode(t *testing.T) {
	// 焦点进程启动于窗口外：仅有 EID3 关联事件，应生成合成节点并成为根
	xml := mkXML([]Event{
		ev(1, 3, "2026-10-18T15:00:00.000+00:00", map[string]string{
			"ProcessGuid": "{OLD}", "ProcessId": "777", "Image": `C:\old.exe`, "DestinationIp": "1.2.3.4",
		}),
	})
	evs := parseXML([]byte(xml))
	res, err := buildProcessTree(evs, "{OLD}", 5000)
	if err != nil {
		t.Fatalf("ProcessTree: %v", err)
	}
	if res.Root.GUID != "{OLD}" || !res.Root.Synthetic {
		t.Fatalf("应生成合成根节点, got guid=%s synthetic=%v", res.Root.GUID, res.Root.Synthetic)
	}
	if res.Root.Image != `C:\old.exe` || res.Root.ProcessID != "777" {
		t.Fatalf("合成节点信息补全失败: %v %v", res.Root.Image, res.Root.ProcessID)
	}
	if res.Root.EventCount != 1 {
		t.Fatalf("事件挂载失败")
	}
}

func TestProcessTreeNotFound(t *testing.T) {
	xml := mkXML([]Event{ev(1, 1, "2026-10-18T15:00:00.000+00:00", map[string]string{"ProcessGuid": "{A}", "Image": "x.exe"})})
	evs := parseXML([]byte(xml))
	if _, err := buildProcessTree(evs, "{MISSING}", 5000); err == nil {
		t.Fatalf("未找到进程时应返回错误")
	}
}

func TestProcessTreeEventsTruncated(t *testing.T) {
	var evs []Event
	for i := 0; i < maxNodeEvents+50; i++ {
		evs = append(evs, ev(1000+i, 3, fmt.Sprintf("2026-10-18T15:%02d:%02d.000+00:00", i/60, i%60),
			map[string]string{"ProcessGuid": "{NOISY}", "Image": "n.exe", "DestinationIp": "10.0.0.1"}))
	}
	res, err := buildProcessTree(evs, "{NOISY}", 5000)
	if err != nil {
		t.Fatalf("ProcessTree: %v", err)
	}
	if !res.Root.EventsTruncated || len(res.Root.Events) != maxNodeEvents || res.Root.EventCount != maxNodeEvents+50 {
		t.Fatalf("截断逻辑错误: truncated=%v len=%d count=%d", res.Root.EventsTruncated, len(res.Root.Events), res.Root.EventCount)
	}
}
