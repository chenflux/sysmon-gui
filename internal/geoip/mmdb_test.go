package geoip

import (
	"math"
	"testing"
)

const (
	tStr = 2
	tDbl = 3
	tU32 = 6
	tMap = 7
)

func encCtrl(typ byte, size int) byte { return typ<<5 | byte(size) }

func encStr(s string) []byte {
	return append([]byte{encCtrl(tStr, len(s))}, s...)
}

func encDbl(f float64) []byte {
	b := make([]byte, 9)
	b[0] = encCtrl(tDbl, 8)
	u := math.Float64bits(f)
	for i := 0; i < 8; i++ {
		b[1+i] = byte(u >> (56 - 8*i))
	}
	return b
}

func encU32Bytes(v uint32) []byte {
	b := []byte{encCtrl(tU32, 4)}
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func put24(b []byte, v uint32) {
	b[0] = byte(v >> 16)
	b[1] = byte(v >> 8)
	b[2] = byte(v)
}

// buildTestMMDB 构造最小 mmdb：
// node0: left->data(US), right->node1; node1: left->data(DE), right->nodeCount(未收录)
func buildTestMMDB(t *testing.T) *MMDB {
	t.Helper()
	names := []byte{encCtrl(tMap, 2)}
	names = append(names, encStr("zh-CN")...)
	names = append(names, encStr("美国")...)
	names = append(names, encStr("en")...)
	names = append(names, encStr("United States")...)

	countryUS := []byte{encCtrl(tMap, 2)}
	countryUS = append(countryUS, encStr("iso_code")...)
	countryUS = append(countryUS, encStr("US")...)
	countryUS = append(countryUS, encStr("names")...)
	countryUS = append(countryUS, names...)

	location := []byte{encCtrl(tMap, 2)}
	location = append(location, encStr("latitude")...)
	location = append(location, encDbl(38.0)...)
	location = append(location, encStr("longitude")...)
	location = append(location, encDbl(-97.0)...)

	recUS := []byte{encCtrl(tMap, 2)}
	recUS = append(recUS, encStr("country")...)
	recUS = append(recUS, countryUS...)
	recUS = append(recUS, encStr("location")...)
	recUS = append(recUS, location...)

	countryDE := []byte{encCtrl(tMap, 2)}
	countryDE = append(countryDE, encStr("iso_code")...)
	countryDE = append(countryDE, encStr("DE")...)
	countryDE = append(countryDE, encStr("names")...)
	deNames := []byte{encCtrl(tMap, 1)}
	deNames = append(deNames, encStr("en")...)
	deNames = append(deNames, encStr("Germany")...)
	countryDE = append(countryDE, deNames...)
	recDE := []byte{encCtrl(tMap, 1)}
	recDE = append(recDE, encStr("country")...)
	recDE = append(recDE, countryDE...)

	nodeCount := uint32(2)
	tree := make([]byte, 12)
	put24(tree[0:3], nodeCount+16+0)                // left -> US 数据
	put24(tree[3:6], 1)                             // right -> node1
	put24(tree[6:9], nodeCount+16+uint32(len(recUS))) // left -> DE 数据
	put24(tree[9:12], nodeCount)                    // right -> 未收录

	full := append(tree, make([]byte, 16)...)
	full = append(full, recUS...)
	full = append(full, recDE...)

	meta := []byte{encCtrl(tMap, 3)}
	meta = append(meta, encStr("node_count")...)
	meta = append(meta, encU32Bytes(nodeCount)...)
	meta = append(meta, encStr("record_size")...)
	meta = append(meta, byte(encCtrl(tU32, 1)), 24) // uint32 单字节编码 24
	meta = append(meta, encStr("database_type")...)
	meta = append(meta, encStr("GeoLite2-City-Test")...)
	full = append(full, []byte(metadataMarker)...)
	full = append(full, meta...)

	return &MMDB{data: full, nodeCount: nodeCount, recordSize: 24, dataStart: uint32(len(tree) + 16)}
}

func TestMMDBTreeRecords(t *testing.T) {
	m := buildTestMMDB(t)
	if r := m.record(0, false); r != m.nodeCount+16 {
		t.Fatalf("node0.left = %d, 期望数据指针 %d", r, m.nodeCount+16)
	}
	if r := m.record(0, true); r != 1 {
		t.Fatalf("node0.right = %d, 期望 1", r)
	}
	if r := m.record(1, true); r != m.nodeCount {
		t.Fatalf("node1.right 应为未收录标记, got %d", r)
	}
}

func TestMMDBLookupUS(t *testing.T) {
	m := buildTestMMDB(t)
	rec, err := m.LookupString("::0.0.0.1") // 全 0 前缀 → 走 left 直达数据
	if err != nil {
		t.Fatal(err)
	}
	if rec == nil {
		t.Fatal("应命中 US 记录")
	}
	country, code, lat, lon := CountryInfo(rec)
	if code != "US" || country != "美国" {
		t.Fatalf("US 记录解析错误: country=%q code=%q", country, code)
	}
	if lat == nil || lon == nil || *lat != 38.0 || *lon != -97.0 {
		t.Fatalf("坐标解析错误: lat=%v lon=%v", lat, lon)
	}
}

func TestMMDBPointerDecode(t *testing.T) {
	// 数据段: [0..2]="US" 字符串; [3..]= map{ "c": pointer→"US" }
	data := make([]byte, 0, 32)
	data = append(data, encStr("US")...)
	ptrOff := len(data)
	data = append(data, encCtrl(tMap, 1))
	data = append(data, encStr("c")...)
	data = append(data, 0x20, 0x00) // 指针: SS=0, high=0, 低字节 0 → 指向数据段偏移 0
	m := &MMDB{data: data, nodeCount: 1, recordSize: 24, dataStart: 0}
	v, _, err := m.decode(uint32(ptrOff))
	if err != nil {
		t.Fatal(err)
	}
	mm, ok := v.(map[string]interface{})
	if !ok || mm["c"] != "US" {
		t.Fatalf("指针解码错误: %#v", v)
	}
}

func TestMMDBNotIncluded(t *testing.T) {
	m := buildTestMMDB(t)
	// node1.right = nodeCount → 未收录; 构造走 right 的地址: 第 1 bit 为 1 且后续 1 bit
	rec, err := m.LookupString("8000::") // bit0=1 → node1, bit1=0 → left(DE)…需要再走 right
	_ = err
	// bit0=1(node0.right→node1), bit1=1(node1.right→nodeCount→未收录)
	rec2, _ := m.LookupString("c000::")
	if rec2 != nil {
		t.Fatalf("未收录路径应返回 nil, got %#v", rec2)
	}
	if rec == nil {
		t.Fatalf("8000:: 应命中 DE 记录")
	}
	country, code, _, _ := CountryInfo(rec)
	if code != "DE" || country != "Germany" {
		t.Fatalf("DE 记录解析错误: %q %q", country, code)
	}
}
