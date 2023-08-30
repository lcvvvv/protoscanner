package protoer

import (
	"regexp"
	"strconv"
	"strings"
)

type Match struct {
	Name     string    `json:"name"`  //匹配器名称
	Matchers []Matcher `json:"match"` //匹配器
}

func (m *Match) MatchString(s string) (versionInfo map[string]string, ok bool) {
	var softFilter string

	for _, matcher := range m.Matchers {
		//实现软筛选
		if softFilter != "" {
			if matcher.Service != softFilter {
				continue
			}
		}

		//logger.Println("开始匹配正则：", m.service, m.patternRegexp.String())
		if matcher.Pattern.MatchString(s) {
			//标记当前正则
			//f.MatchRegexString = m.patternRegexp.String()
			if matcher.Soft {
				//如果为软捕获，这设置筛选器
				softFilter = matcher.Service
				versionInfo = matcher.VersionInfo(s)
				continue
			} else {
				//如果为硬捕获则直接获取指纹信息
				return matcher.VersionInfo(s), true
			}
		}
	}

	if softFilter != "" {
		return versionInfo, true
	} else {
		return nil, false
	}
}

type Matcher struct {
	Soft    bool   `json:"soft"`
	Service string `json:"service"`
	Pattern Regexp `json:"pattern"`

	ProductName string `json:"product_name"` //	p/vendorproductname/
	Version     string `json:"version"`      //	v/version/
	Info        string `json:"info"`         //	i/info/
	Hostname    string `json:"hostname"`     //	h/hostname/
	OS          string `json:"os"`           //	o/operatingsystem/
	DeviceType  string `json:"device_type"`  //	d/devicetype/
}

func (m *Matcher) VersionInfo(s string) (info map[string]string) {
	info = make(map[string]string)
	info["service"] = m.Service
	info["product_name"] = m.resolveInfo(s, m.ProductName)
	info["version"] = m.resolveInfo(s, m.Version)
	info["info"] = m.resolveInfo(s, m.Info)
	info["hostname"] = m.resolveInfo(s, m.Hostname)
	info["os"] = m.resolveInfo(s, m.OS)
	info["device_type"] = m.resolveInfo(s, m.DeviceType)
	return info
}

var (
	infoTagRegexP = regexp.MustCompile(`\$P\((\d)\)`)
	infoTagRegex  = regexp.MustCompile(`\$(\d)`)
)

func (m *Matcher) resolveInfo(s, pattern string) string {
	if len(m.Pattern.FindStringSubmatch(s)) == 1 {
		return pattern
	}

	if pattern == "" {
		return pattern
	}

	sArr := m.Pattern.FindStringSubmatch(s)

	if infoTagRegexP.MatchString(pattern) {
		pattern = infoTagRegexP.ReplaceAllStringFunc(pattern, func(repl string) string {
			a := infoTagRegexP.FindStringSubmatch(repl)[1]
			return "$" + a
		})
	}

	if infoTagRegex.MatchString(pattern) {
		pattern = infoTagRegex.ReplaceAllStringFunc(pattern, func(repl string) string {
			i, _ := strconv.Atoi(infoTagRegex.FindStringSubmatch(repl)[1])
			return sArr[i]
		})
	}

	pattern = strings.ReplaceAll(pattern, "\n", "")
	pattern = strings.ReplaceAll(pattern, "\r", "")
	return pattern
}
