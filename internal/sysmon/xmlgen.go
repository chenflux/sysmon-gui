package sysmon

import (
	"fmt"
	"strings"
)

func escapeXML(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}

func isJoinOp(op string) bool {
	switch op {
	case "contains any", "contains all", "excludes any":
		return true
	}
	return false
}

func GenerateXML(cfg *RuleConfig) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("规则配置为空")
	}
	schema := cfg.SchemaVersion
	if schema == "" {
		schema = "4.90"
	}
	hash := cfg.HashAlgorithms
	if hash == "" {
		hash = "md5,sha1,sha256"
	}

	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>` + "\n")
	fmt.Fprintf(&b, "<Sysmon schemaversion=\"%s\">\n", escapeXML(schema))
	fmt.Fprintf(&b, "  <HashAlgorithms>%s</HashAlgorithms>\n", escapeXML(hash))
	if cfg.DnsLookup {
		b.WriteString("  <DnsLookup>true</DnsLookup>\n")
	} else {
		b.WriteString("  <DnsLookup>false</DnsLookup>\n")
	}
	b.WriteString("  <CheckRevocation/>\n")
	b.WriteString("  <EventFiltering>\n")

	for _, r := range cfg.Rules {
		if r == nil || !r.Enabled {
			continue
		}
		onmatch := r.OnMatch
		if onmatch != "exclude" {
			onmatch = "include"
		}
		activeGroups := 0
		for _, g := range r.Groups {
			if g == nil {
				continue
			}
			n := 0
			for _, c := range g.Conditions {
				if c != nil && strings.TrimSpace(c.Field) != "" && len(c.Values) > 0 {
					n++
				}
			}
			if n > 0 {
				activeGroups++
			}
		}
		if activeGroups == 0 {
			if onmatch == "include" {
				// 无条件 include = 记录该类型全部事件，输出空规则元素
				name := strings.TrimSpace(r.Name)
				fmt.Fprintf(&b, "    <RuleGroup name=\"%s\" groupRelation=\"or\">\n", escapeXML(name))
				fmt.Fprintf(&b, "      <%s onmatch=\"include\"/>\n", escapeXML(r.EventType))
				b.WriteString("    </RuleGroup>\n")
			}
			continue
		}

		idx := 0
		for _, g := range r.Groups {
			if g == nil {
				continue
			}
			hasCond := false
			for _, c := range g.Conditions {
				if c != nil && strings.TrimSpace(c.Field) != "" && len(c.Values) > 0 {
					hasCond = true
					break
				}
			}
			if !hasCond {
				continue
			}
			idx++

			rel := g.Relation
			if rel != "and" && rel != "or" {
				rel = "or"
			}
			name := strings.TrimSpace(r.Name)
			if activeGroups > 1 {
				name = fmt.Sprintf("%s #%d", name, idx)
			}
			fmt.Fprintf(&b, "    <RuleGroup name=\"%s\" groupRelation=\"%s\">\n", escapeXML(name), escapeXML(rel))
			fmt.Fprintf(&b, "      <%s onmatch=\"%s\">\n", escapeXML(r.EventType), escapeXML(onmatch))

			for _, c := range g.Conditions {
				if c == nil || strings.TrimSpace(c.Field) == "" || len(c.Values) == 0 {
					continue
				}
				field := escapeXML(strings.TrimSpace(c.Field))
				op := escapeXML(c.Op)
				if isJoinOp(c.Op) && len(c.Values) > 1 {
					vals := make([]string, 0, len(c.Values))
					for _, v := range c.Values {
						if strings.TrimSpace(v) != "" {
							vals = append(vals, escapeXML(v))
						}
					}
					fmt.Fprintf(&b, "        <%s condition=\"%s\">%s</%s>\n", field, op, strings.Join(vals, ";"), field)
				} else {
					for _, v := range c.Values {
						if strings.TrimSpace(v) == "" {
							continue
						}
						fmt.Fprintf(&b, "        <%s condition=\"%s\">%s</%s>\n", field, op, escapeXML(v), field)
					}
				}
			}
			fmt.Fprintf(&b, "      </%s>\n", escapeXML(r.EventType))
			b.WriteString("    </RuleGroup>\n")
		}
	}

	b.WriteString("  </EventFiltering>\n")
	b.WriteString("</Sysmon>\n")
	return b.String(), nil
}
