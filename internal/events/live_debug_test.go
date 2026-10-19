package events

import "testing"

// Live 测试：仅在本机存在 Sysmon 通道时有效，否则跳过（兼容 CI）。
func liveEID1(t *testing.T) []Event {
	t.Helper()
	evs, err := fetchWindow(Options{Fetch: 5000, EventID: 1})
	if err != nil {
		t.Skipf("本机无 Sysmon 通道: %v", err)
	}
	if len(evs) == 0 {
		t.Skip("无 EID1 事件")
	}
	return evs
}

func TestLiveTreeWithGuidedLookup(t *testing.T) {
	DebugLogf = func(format string, args ...interface{}) {
		t.Logf("DBG: "+format, args...)
	}
	eid1s := liveEID1(t)
	guid := dataVal(eid1s[0], "ProcessGuid")
	res, err := ProcessTree(guid, 5000, 0)
	if err != nil {
		t.Fatalf("ProcessTree 失败: %v", err)
	}
	if res.FocusGUID != guid {
		t.Fatalf("焦点错误: %v != %v", res.FocusGUID, guid)
	}
	// 焦点必须是真实节点（有 EID1，非合成）
	if findTreeNodeLive(res.Root, guid) == nil {
		t.Fatalf("树中缺少焦点节点")
	}
}

func findTreeNodeLive(n *ProcessNode, guid string) *ProcessNode {
	if n == nil {
		return nil
	}
	if n.GUID == guid {
		return n
	}
	for _, c := range n.Children {
		if r := findTreeNodeLive(c, guid); r != nil {
			return r
		}
	}
	return nil
}

func TestLiveGuidedXPath(t *testing.T) {
	eid1s := liveEID1(t)
	guid := dataVal(eid1s[0], "ProcessGuid")
	img := dataVal(eid1s[0], "Image")
	_ = img
	// 原生窗口 vs wevtutil 窗口：集合差分析
	nat, natErr := fetchNative(Options{Fetch: 200, EventID: 1}, 200)
	wvt, wvtErr := fetchWevtutil(Options{Fetch: 200, EventID: 1}, 200)
	t.Logf("native len=%d err=%v | wevtutil len=%d err=%v", len(nat), natErr, len(wvt), wvtErr)
	setN := map[string]bool{}
	for _, ev := range nat {
		setN[dataVal(ev, "ProcessGuid")] = true
	}
	onlyW := []string{}
	for _, ev := range wvt {
		g := dataVal(ev, "ProcessGuid")
		if !setN[g] {
			if len(g) > 14 {
				g = g[9:23]
			}
			onlyW = append(onlyW, g)
		}
	}
	t.Logf("仅在 wevtutil 窗口中的 guid 数=%d 示例=%v", len(onlyW), onlyW[:min(5, len(onlyW))])
	inNat := setN[guid]
	t.Logf("焦点 guid ∈ native=%v (nat len=%d)", inNat, len(nat))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
