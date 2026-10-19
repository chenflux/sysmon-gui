package sysmon

import "testing"

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
