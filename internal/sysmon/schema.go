package sysmon

import (
	"encoding/xml"
	"io"
	"os/exec"
	"strings"
	"time"
)

type SchemaInfo struct {
	Fields     map[string][]string `json:"fields"`
	Ops        map[string]bool     `json:"-"`
	SchemaVer  string              `json:"schema_version"`
	BinaryVer  string              `json:"binary_version"`
	FromSysmon bool                `json:"from_sysmon"`
}

type schemaManifest struct {
	SchemaVersion  string `xml:"schemaversion,attr"`
	BinaryVersion  string `xml:"binaryversion,attr"`
	Events         []struct {
		Name      string `xml:"name,attr"`
		RuleName  string `xml:"rulename,attr"`
		RuleDefault string `xml:"ruledefault,attr"`
		Data      []struct {
			Name string `xml:"name,attr"`
		} `xml:"data"`
	} `xml:"event"`
}

func fallbackSchema() *SchemaInfo {
	fields := map[string][]string{}
	for t, f := range eventFields {
		fields[t] = f
	}
	ops := map[string]bool{}
	for _, o := range operators {
		ops[o.Op] = true
	}
	return &SchemaInfo{Fields: fields, Ops: ops}
}

func ParseSchema(output string) (*SchemaInfo, bool) {
	idx := strings.Index(output, "<manifest")
	if idx == -1 {
		return nil, false
	}
	dec := xml.NewDecoder(strings.NewReader(output[idx:]))
	fields := map[string][]string{}
	schemaVer := ""
	binaryVer := ""
	curRule := ""
	seenByRule := map[string]map[string]bool{}
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, false
		}
		switch se := tok.(type) {
		case xml.StartElement:
			switch se.Name.Local {
			case "manifest":
				for _, a := range se.Attr {
					switch a.Name.Local {
					case "schemaversion":
						schemaVer = a.Value
					case "binaryversion":
						binaryVer = a.Value
					}
				}
			case "event":
				curRule = ""
				for _, a := range se.Attr {
					if a.Name.Local == "rulename" && a.Value != "" {
						curRule = a.Value
						if _, ok := fields[curRule]; !ok {
							fields[curRule] = []string{}
							seenByRule[curRule] = map[string]bool{}
						}
					}
				}
			case "data":
				if curRule == "" {
					continue
				}
				for _, a := range se.Attr {
					if a.Name.Local == "name" && a.Value != "" && !seenByRule[curRule][a.Value] {
						fields[curRule] = append(fields[curRule], a.Value)
						seenByRule[curRule][a.Value] = true
					}
				}
			}
		case xml.EndElement:
			if se.Name.Local == "event" {
				curRule = ""
			}
		}
	}
	if len(fields) == 0 {
		return nil, false
	}
	ops := map[string]bool{}
	for _, o := range operators {
		ops[o.Op] = true
	}
	return &SchemaInfo{
		Fields:     fields,
		Ops:        ops,
		SchemaVer:  schemaVer,
		BinaryVer:  binaryVer,
		FromSysmon: true,
	}, true
}

// Schema 返回校验用 schema；优先从本机 Sysmon (-s) 动态解析，失败时回退内置清单。
// 缓存于 Manager 实例（下载 Sysmon 后可经 RefreshExePath 重置重载）。
func (m *Manager) Schema() *SchemaInfo {
	m.schemaOnce.Do(func() {
		m.schemaCache = fallbackSchema()
		if !fileExists(m.ExePath()) {
			return
		}
		cmd := exec.Command(m.ExePath(), "-s")
		hideWindow(cmd)
		out, _, err := execWithTimeout(cmd, 30*time.Second)
		if err != nil {
			return
		}
		if sc, ok := ParseSchema(out); ok {
			m.schemaCache = sc
			Logf("已加载 Sysmon 官方 schema v%s (binary %s)，共 %d 个事件类型", sc.SchemaVer, sc.BinaryVer, len(sc.Fields))
		}
	})
	return m.schemaCache
}
