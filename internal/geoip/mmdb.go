//go:build windows

package geoip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strings"
)

// MMDB 自实现的 MaxMind DB (GeoLite2/GeoIP2) 只读解析器，
// 支持二进制搜索树与数据段解码，无第三方依赖。
// 格式规范: https://maxmind.github.io/MaxMind-DB/
type MMDB struct {
	data       []byte
	nodeCount  uint32
	recordSize uint16
	dataStart  uint32
	DbType     string
}

const metadataMarker = "\xab\xed\xef"

var errBadMMDB = errors.New("无效的 MaxMind DB 文件")

// OpenMMDB 打开并解析 mmdb 文件（GeoLite2-Country / GeoLite2-City 等）。
func OpenMMDB(path string) (*MMDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 16 {
		return nil, errBadMMDB
	}
	// 元数据标记位于文件尾部区域，取最后一次出现
	tail := data
	if len(tail) > 128*1024 {
		tail = tail[len(tail)-128*1024:]
	}
	idx := strings.LastIndex(string(tail), metadataMarker)
	if idx < 0 {
		return nil, errBadMMDB
	}
	m := &MMDB{data: data}
	metaOff := uint32(len(data) - len(tail) + idx + len(metadataMarker))
	meta, _, err := m.decode(metaOff)
	if err != nil {
		return nil, fmt.Errorf("mmdb 元数据解析失败: %w", err)
	}
	mm, ok := meta.(map[string]interface{})
	if !ok {
		return nil, errBadMMDB
	}
	nc, _ := mm["node_count"].(uint64)
	rs, _ := mm["record_size"].(uint64)
	if nc == 0 || (rs != 24 && rs != 28 && rs != 32) {
		return nil, errBadMMDB
	}
	m.nodeCount = uint32(nc)
	m.recordSize = uint16(rs)
	if t, ok := mm["database_type"].(string); ok {
		m.DbType = t
	}
	treeBytes := uint32(nc) * uint32(rs) * 2 / 8
	m.dataStart = treeBytes + 16
	if uint64(m.dataStart) >= uint64(len(data)) {
		return nil, errBadMMDB
	}
	return m, nil
}

// record 读取节点 node 的左右记录值。
func (m *MMDB) record(node uint32, right bool) uint32 {
	off := uint64(node) * uint64(m.recordSize) * 2 / 8
	switch m.recordSize {
	case 24:
		off += map[bool]uint64{false: 0, true: 3}[right]
		b := m.data[off : off+3]
		return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	case 28:
		b := m.data[off : off+7]
		if right {
			return uint32(b[3]&0x0f)<<24 | uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
		}
		return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	default: // 32
		off += map[bool]uint64{false: 0, true: 4}[right]
		return binary.BigEndian.Uint32(m.data[off : off+4])
	}
}

// LookupString 解析 IP 并返回其记录（顶层 map）。
func (m *MMDB) LookupString(ipStr string) (map[string]interface{}, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("无效 IP: %s", ipStr)
	}
	addr := ip.To16()
	if addr == nil {
		return nil, fmt.Errorf("无效 IP: %s", ipStr)
	}
	node := uint32(0)
	for i := 0; i < 128; i++ {
		if node >= m.nodeCount {
			break
		}
		bit := (addr[i/8] >> (7 - uint(i%8))) & 1
		r := m.record(node, bit == 1)
		if r == m.nodeCount {
			return nil, nil // 未收录
		}
		if r > m.nodeCount {
			// 指向数据段
			off := m.dataStart + r - m.nodeCount - 16
			v, _, err := m.decode(off)
			if err != nil {
				return nil, err
			}
			if mm, ok := v.(map[string]interface{}); ok {
				return mm, nil
			}
			return nil, nil
		}
		node = r
	}
	return nil, nil
}

/* ---- 数据段解码 ---- */

func (m *MMDB) decode(off uint32) (interface{}, uint32, error) {
	if uint64(off) >= uint64(len(m.data)) {
		return nil, 0, errBadMMDB
	}
	ctrl := m.data[off]
	off++
	typ := ctrl >> 5
	size := uint32(ctrl & 0x1f)

	if typ == 0 { // 扩展类型
		if uint64(off) >= uint64(len(m.data)) {
			return nil, 0, errBadMMDB
		}
		typ = m.data[off]
		off++
	}
	// 扩展长度
	switch size {
	case 29:
		size = uint32(m.data[off]) + 29
		off++
	case 30:
		size = uint32(binary.BigEndian.Uint16(m.data[off:off+2])) + 285
		off += 2
	case 31:
		size = (uint32(m.data[off])<<16 | uint32(m.data[off+1])<<8 | uint32(m.data[off+2])) + 65813
		off += 3
	}

	switch typ {
	case 1: // pointer
		ss := (ctrl >> 3) & 0x3
		high := uint32(ctrl & 0x07)
		var ptr uint32
		switch ss {
		case 0:
			ptr = high<<8 | uint32(m.data[off])
			off++
		case 1:
			ptr = (high<<16 | uint32(m.data[off])<<8 | uint32(m.data[off+1])) + 2048
			off += 2
		case 2:
			ptr = (high<<24 | uint32(m.data[off])<<16 | uint32(m.data[off+1])<<8 | uint32(m.data[off+2])) + 526336
			off += 3
		default:
			ptr = binary.BigEndian.Uint32(m.data[off : off+4])
			off += 4
		}
		v, _, err := m.decode(m.dataStart + ptr)
		if err != nil {
			return nil, 0, err
		}
		return v, off, nil
	case 2: // utf8 string
		end := off + size
		if uint64(end) > uint64(len(m.data)) {
			return nil, 0, errBadMMDB
		}
		return string(m.data[off:end]), end, nil
	case 3: // double
		if size != 8 {
			return nil, 0, errBadMMDB
		}
		return math.Float64frombits(binary.BigEndian.Uint64(m.data[off : off+8])), off + 8, nil
	case 4: // bytes
		end := off + size
		return string(m.data[off:end]), end, nil
	case 5, 6, 9, 10: // uint16/32/64/128
		var v uint64
		for i := uint32(0); i < size && i < 8; i++ {
			v = v<<8 | uint64(m.data[off+i])
		}
		return v, off + size, nil
	case 7: // map
		out := map[string]interface{}{}
		var lastErr error
		for i := uint32(0); i < size; i++ {
			k, nOff, err := m.decode(off)
			if err != nil {
				lastErr = err
				break
			}
			off = nOff
			key, _ := k.(string)
			v, nOff2, err := m.decode(off)
			if err != nil {
				lastErr = err
				break
			}
			off = nOff2
			out[key] = v
		}
		if lastErr != nil && len(out) == 0 {
			return nil, 0, lastErr
		}
		return out, off, nil
	case 8: // int32
		var v int32
		for i := uint32(0); i < size && i < 4; i++ {
			v = v<<8 | int32(int8(m.data[off+i]))
		}
		return v, off + size, nil
	case 11: // array
		arr := make([]interface{}, 0, size)
		for i := uint32(0); i < size; i++ {
			v, nOff, err := m.decode(off)
			if err != nil {
				break
			}
			off = nOff
			arr = append(arr, v)
		}
		return arr, off, nil
	case 14: // boolean：size 字段即取值
		return size == 1, off, nil
	case 15: // float
		if size != 4 {
			return nil, 0, errBadMMDB
		}
		return float64(math.Float32frombits(binary.BigEndian.Uint32(m.data[off : off+4]))), off + 4, nil
	default:
		return nil, 0, fmt.Errorf("mmdb 不支持的数据类型 %d", typ)
	}
}

// CountryInfo 从记录中提取国家信息（优先中文名）与可选坐标。
func CountryInfo(rec map[string]interface{}) (country, code string, lat, lon *float64) {
	c, _ := rec["country"].(map[string]interface{})
	if c == nil {
		c, _ = rec["registered_country"].(map[string]interface{})
	}
	if c != nil {
		code, _ = c["iso_code"].(string)
		if names, ok := c["names"].(map[string]interface{}); ok {
			if zh, ok := names["zh-CN"].(string); ok && zh != "" {
				country = zh
			} else if en, ok := names["en"].(string); ok {
				country = en
			}
		}
	}
	if loc, ok := rec["location"].(map[string]interface{}); ok {
		if la, ok := loc["latitude"].(float64); ok {
			if lo, ok := loc["longitude"].(float64); ok {
				lat, lon = &la, &lo
			}
		}
	}
	return
}
