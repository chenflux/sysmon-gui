package sysmon

import (
	"strings"
	"testing"
)

func TestDecodeBytesMixedEncoding(t *testing.T) {
	// Sysmon 控制台输出混排：ASCII 横幅 + UTF-16LE 错误行
	banner := []byte("System Monitor v15.22 - System activity monitor\r\n")
	msg := []uint16(nil)
	for _, c := range "Event manifest installation failed with last error:" {
		msg = append(msg, uint16(c))
	}
	var u16 []byte
	for _, u := range msg {
		u16 = append(u16, byte(u), byte(u>>8))
	}
	mixed := append(append([]byte{}, banner...), u16...)
	mixed = append(mixed, '\r', '\n')

	got := decodeBytes(mixed)
	if !strings.Contains(got, "System Monitor v15.22") {
		t.Fatalf("ASCII 横幅解码失败: %q", got)
	}
	if !strings.Contains(got, "Event manifest installation failed") {
		t.Fatalf("UTF-16 错误行解码失败: %q", got)
	}
}

func TestDecodeBytesBomlessUTF16Whole(t *testing.T) {
	// Sysmon -s 的 schema 输出：无 BOM 的纯 UTF-16LE（NUL 约占一半）
	text := "\r\nSystem Monitor v15.22\r\n<manifest schemaversion=\"4.91\" binaryversion=\"18\"><event name=\"process\" rulename=\"ProcessCreate\"><data name=\"Image\"/></event></manifest>"
	var u16 []byte
	for _, c := range text {
		u16 = append(u16, byte(c), byte(c>>8))
	}
	got := decodeBytes(u16)
	if !strings.Contains(got, "System Monitor v15.22") || !strings.Contains(got, "<manifest schemaversion=\"4.91\"") {
		t.Fatalf("BOM-less UTF-16 整体解码失败: %.120q", got)
	}
	if strings.ContainsRune(got, 0) {
		t.Fatalf("解码结果残留 NUL: %.80q", got)
	}
}

func TestIsTransientManifestFail(t *testing.T) {
	if !isTransientManifestFail(errString("System Monitor ... Event manifest installation failed with last error: ??????? (exit status 13)")) {
		t.Fatal("应识别为瞬时清单失败")
	}
	if isTransientManifestFail(errString("access is denied")) {
		t.Fatal("权限错误不应误判为瞬时清单失败")
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestIsGenuineSysmonPath(t *testing.T) {
	genuine := []string{
		`C:\WINDOWS\Sysmon64.exe`,
		`c:\windows\sysmon.exe`,
		`\??\C:\Windows\Sysmon.sys`,
		`\SystemRoot\SysmonDrv.sys`,
	}
	for _, p := range genuine {
		if !isGenuineSysmonPath(p) {
			t.Fatalf("%q 应被识别为正版 Sysmon 路径", p)
		}
	}
	impostors := []string{
		`\??\C:\Program Files (x86)\eTrust\SdpDns\sysmon.sys`, // eTrust 同名服务
		`C:\Program Files\Vendor\sysmon64.exe`,
		``,
		`C:\WINDOWS\explorer.exe`, // 系统目录但非 sysmon 文件
		`\??\D:\Tools\sysmon64.exe`,
	}
	for _, p := range impostors {
		if isGenuineSysmonPath(p) {
			t.Fatalf("%q 不应被识别为正版 Sysmon 路径", p)
		}
	}
}

func TestParseSchemaBinaryVersion(t *testing.T) {
	out := `<manifest schemaversion="4.91" binaryversion="15.22">
		<event name="process" rulename="ProcessCreate"><data name="Image"/><data name="CommandLine"/></event>
	</manifest>`
	sc, ok := ParseSchema(out)
	if !ok {
		t.Fatalf("schema 解析失败")
	}
	if sc.SchemaVer != "4.91" || sc.BinaryVer != "15.22" {
		t.Fatalf("版本解析错误: schema=%q binary=%q", sc.SchemaVer, sc.BinaryVer)
	}
	if len(sc.Fields["ProcessCreate"]) != 2 {
		t.Fatalf("字段解析错误: %v", sc.Fields["ProcessCreate"])
	}
}
