package events

import "testing"

func TestFilterEventsMultiKeyword(t *testing.T) {
	evs := []Event{
		{EventID: 10, Data: []KV{{Name: "SourceImage", Value: `C:\x\lsass.exe`}}},
		{EventID: 1, Data: []KV{{Name: "CommandLine", Value: "badproc.exe -enc AAA"}}},
		{EventID: 3, Data: []KV{{Name: "DestinationIp", Value: "1.2.3.4"}}},
	}
	out := filterEvents(evs, Options{Keyword: "lsass|badproc"})
	if len(out) != 2 {
		t.Fatalf("多值关键字应命中 2 条, got %d", len(out))
	}
	out = filterEvents(evs, Options{Keyword: "lsass"})
	if len(out) != 1 {
		t.Fatalf("单值关键字应命中 1 条, got %d", len(out))
	}
	// 空片段不应导致全量匹配
	out = filterEvents(evs, Options{Keyword: "||"})
	if len(out) != 3 {
		t.Fatalf("空关键字应全量返回, got %d", len(out))
	}
}
