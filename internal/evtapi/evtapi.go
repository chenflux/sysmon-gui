//go:build windows

// Package evtapi 封装 Windows 事件日志 API (wevtapi.dll)，
// 替代 wevtutil 子进程：无进程创建开销、支持远超 5000 条的全量扫描。
package evtapi

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	wevtapi       = syscall.NewLazyDLL("wevtapi.dll")
	procEvtQuery  = wevtapi.NewProc("EvtQuery")
	procEvtNext   = wevtapi.NewProc("EvtNext")
	procEvtRender = wevtapi.NewProc("EvtRender")
	procEvtClose  = wevtapi.NewProc("EvtClose")
)

const (
	evtQueryChannelPath = 0x1
	// EvtQueryForwardDirection = 0x100, EvtQueryReverseDirection = 0x200 (winevt.h)
	evtQueryReverseDirection = 0x200
	evtRenderEventXml        = 0x1
	evtNextTimeoutInfinite   = 0xFFFFFFFF
	errEvtChannelNotFound    = 15002
	errAccessDenied          = 5
	errNoMoreItems           = 259 // ERROR_NO_MORE_ITEMS
)

// Available 检测 wevtapi 是否可用（极老系统回退 wevtutil）。
func Available() bool {
	return procEvtQuery.Find() == nil
}

// EachEvent 反向（最新在前）遍历通道事件，逐条回调原始 XML 文本。
// max <= 0 表示不限制条数；回调返回 error 时提前终止并原样返回。
func EachEvent(channel, xpath string, max int, cb func(xmlText string) error) error {
	cp, err := syscall.UTF16PtrFromString(channel)
	if err != nil {
		return err
	}
	var xp *uint16
	if xpath != "" {
		if xp, err = syscall.UTF16PtrFromString(xpath); err != nil {
			return err
		}
	}
	h, _, e := procEvtQuery.Call(0, uintptr(unsafe.Pointer(cp)), uintptr(unsafe.Pointer(xp)),
		evtQueryChannelPath|evtQueryReverseDirection)
	if h == 0 {
		if en, ok := e.(syscall.Errno); ok {
			if int(en) == errEvtChannelNotFound {
				return fmt.Errorf("未找到事件日志通道: %s", channel)
			}
			if int(en) == errAccessDenied {
				return fmt.Errorf("读取事件日志被拒绝 (需要相应权限)")
			}
		}
		return fmt.Errorf("EvtQuery 失败: %v", e)
	}
	defer procEvtClose.Call(h)

	const batch = 256
	handles := make([]uintptr, batch)
	total := 0
	for max <= 0 || total < max {
		var got uint32
		r, _, e := procEvtNext.Call(h, batch, uintptr(unsafe.Pointer(&handles[0])),
			evtNextTimeoutInfinite, 0, uintptr(unsafe.Pointer(&got)))
		if r == 0 {
			if en, ok := e.(syscall.Errno); ok && int(en) == errNoMoreItems {
				break
			}
			return fmt.Errorf("EvtNext 失败: %v", e)
		}
		for i := 0; i < int(got); i++ {
			if handles[i] == 0 {
				continue
			}
			s, err := renderXML(handles[i])
			procEvtClose.Call(handles[i])
			handles[i] = 0
			if err != nil {
				return err
			}
			total++
			if err := cb(s); err != nil {
				return err
			}
			if max > 0 && total >= max {
				return nil
			}
		}
	}
	return nil
}

func renderXML(h uintptr) (string, error) {
	var bufSize, bufUsed uint32
	procEvtRender.Call(0, h, evtRenderEventXml, 0, 0,
		uintptr(unsafe.Pointer(&bufSize)), uintptr(unsafe.Pointer(&bufUsed)))
	if bufSize == 0 {
		return "", fmt.Errorf("EvtRender 无法确定缓冲区大小")
	}
	buf := make([]uint16, bufSize/2+2)
	r, _, e := procEvtRender.Call(0, h, evtRenderEventXml, uintptr(len(buf)*2),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bufSize)), uintptr(unsafe.Pointer(&bufUsed)))
	if r == 0 {
		return "", fmt.Errorf("EvtRender 失败: %v", e)
	}
	s := syscall.UTF16ToString(buf)
	if i := strings.Index(s, "?>"); i >= 0 && strings.HasPrefix(strings.TrimSpace(s), "<?xml") {
		s = s[i+2:]
	}
	return s, nil
}
