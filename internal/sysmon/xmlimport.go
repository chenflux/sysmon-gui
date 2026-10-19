package sysmon

import (
	"encoding/xml"
	"fmt"
	"strings"
)

type xmlImportConfig struct {
	XMLName        xml.Name         `xml:"Sysmon"`
	SchemaVersion  string           `xml:"schemaversion,attr"`
	HashAlgorithms string           `xml:"HashAlgorithms"`
	DnsLookup      string           `xml:"DnsLookup"`
	RuleGroups     []xmlImportGroup `xml:"EventFiltering>RuleGroup"`
}

type xmlImportGroup struct {
	Name          string           `xml:"name,attr"`
	GroupRelation string           `xml:"groupRelation,attr"`
	Disabled      string           `xml:"disabled,attr"`
	Events        []xmlImportEvent `xml:",any"`
}

type xmlImportEvent struct {
	XMLName    xml.Name
	OnMatch    string               `xml:"onmatch,attr"`
	Conditions []xmlImportCondition `xml:",any"`
}

type xmlImportCondition struct {
	XMLName   xml.Name
	Condition string `xml:"condition,attr"`
	Value     string `xml:",chardata"`
}

func isJoinOpForSplit(op string) bool {
	switch op {
	case "contains any", "contains all", "excludes any":
		return true
	}
	return false
}

// ParseSysmonXML 将既有 Sysmon 配置 XML 解析为本工具的规则模型。
func ParseSysmonXML(data []byte) (*RuleConfig, int, error) {
	var xc xmlImportConfig
	if err := xml.Unmarshal(data, &xc); err != nil {
		return nil, 0, fmt.Errorf("XML 解析失败: %w", err)
	}
	if xc.XMLName.Local == "" {
		return nil, 0, fmt.Errorf("未找到 <Sysmon> 根元素，请确认是 Sysmon 配置文件")
	}

	cfg := &RuleConfig{
		SchemaVersion:  xc.SchemaVersion,
		HashAlgorithms: xc.HashAlgorithms,
		DnsLookup:      strings.EqualFold(strings.TrimSpace(xc.DnsLookup), "true"),
		Rules:          []*Rule{},
	}
	if cfg.SchemaVersion == "" {
		cfg.SchemaVersion = "4.90"
	}
	if cfg.HashAlgorithms == "" {
		cfg.HashAlgorithms = "md5,sha1,sha256"
	}

	condCount := 0
	nameCounters := map[string]int{}
	for _, g := range xc.RuleGroups {
		disabled := strings.EqualFold(strings.TrimSpace(g.Disabled), "true")
		for _, ev := range g.Events {
			eventType := ev.XMLName.Local
			if eventType == "" {
				continue
			}
			onmatch := ev.OnMatch
			if onmatch == "" {
				onmatch = "include"
			}
			conds := []*Condition{}
			for _, c := range ev.Conditions {
				field := c.XMLName.Local
				value := strings.TrimSpace(c.Value)
				if field == "" || value == "" {
					continue
				}
				op := c.Condition
				if op == "" {
					op = "is"
				}
				var values []string
				if isJoinOpForSplit(op) {
					for _, v := range strings.Split(value, ";") {
						if v = strings.TrimSpace(v); v != "" {
							values = append(values, v)
						}
					}
				} else {
					values = []string{value}
				}
				conds = append(conds, &Condition{Field: field, Op: op, Values: values})
				condCount++
			}

			name := strings.TrimSpace(g.Name)
			if name == "" {
				key := eventType + "-" + onmatch
				nameCounters[key]++
				name = fmt.Sprintf("导入-%s-%s-%d", eventType, onmatch, nameCounters[key])
			}

			rule := &Rule{
				ID:        NewRuleID(),
				Name:      name,
				EventType: eventType,
				OnMatch:   onmatch,
				Enabled:   !disabled,
				Groups:    []*CondGroup{{Relation: g.GroupRelation, Conditions: conds}},
			}
			if rule.Groups[0].Relation != "and" && rule.Groups[0].Relation != "or" {
				rule.Groups[0].Relation = "or"
			}
			if len(conds) == 0 {
				if onmatch == "include" {
					// Sysmon 语义：空 include 规则 = 记录该类型全部事件，保留启用
					rule.Enabled = true
					rule.Note = "无条件规则：记录该类型全部事件（原配置为空规则）"
				} else {
					// 空 exclude = 排除全部事件，属危险写法，保持停用
					rule.Enabled = false
					rule.Note = "导入时该规则没有任何条件（空排除规则会丢弃全部事件，已自动停用）"
				}
			} else if rule.Note == "" {
				rule.Note = "由 XML 导入"
			}
			cfg.Rules = append(cfg.Rules, rule)
		}
	}

	if len(cfg.Rules) == 0 {
		return nil, 0, fmt.Errorf("未在 <EventFiltering> 中找到任何规则")
	}
	return cfg, condCount, nil
}
