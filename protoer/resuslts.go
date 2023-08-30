package protoer

import (
	"crypto/tls"
	"github.com/lcvvvv/ranger"
	"time"
)

type Results struct {
	main   Result
	status Status

	list    []Result
	scanned *ranger.Ranger[string]
}

func (r *Results) Value() Result {
	return r.main
}

func (r *Results) History() []Result {
	return r.list
}

func (r *Results) Status() Status {
	return r.main.Status
}

func (r *Results) Service() string {
	length := len(r.list)
	if length == 0 {
		return ""
	}
	return r.list[length-1].Service()
}

func (r *Results) push(results ...Result) {
	for _, result := range results {
		r.scanned.Push(r.reqName(result.ProbeName, result.IsSSL))
		r.list = append(r.list, result)

		if result.Status >= r.status {
			r.status = result.Status
			r.main = result
		}
	}
}

func (r *Results) isScanned(name string, ssl bool) bool {
	return r.scanned.Contains(r.reqName(name, ssl))
}

func (r *Results) reqName(name string, isSSL bool) string {
	if isSSL {
		return "SSL_" + name
	} else {
		return "TCP_" + name
	}
}

type Result struct {
	Status Status

	RunningTime time.Duration

	IsSSL    bool
	TLSState tls.ConnectionState

	ProbeName string
	ProbeData string

	Banner string

	errMsg error

	VersionInfo map[string]string
}

func (r *Result) Error() string {
	return r.errMsg.Error()
}

func (r *Result) Service() string {
	return r.VersionInfo["service"]
}

func (r *Result) statTime() func() {
	now := time.Now()
	return func() {
		r.RunningTime = time.Since(now)
	}
}

func (r *Result) loadProbe(address string, p Probe, isSSL bool) {
	r.ProbeData = string(p.GetProbeData(p.Network, address))
	r.ProbeName = p.Name
	r.IsSSL = isSSL
	r.Status = Closed
}

func (r *Result) loadBanner(banner string) {
	r.Banner = banner
	r.Status = NotMatched
}

func (r *Result) loadTLSState(state tls.ConnectionState) {
	r.TLSState = state
}

func (r *Result) closed(err error) Result {
	r.errMsg = err
	r.Status = Closed
	return *r
}

func (r *Result) opened(err error) Result {
	r.errMsg = err
	r.Status = Opened
	return *r
}

func (r *Result) onlySSL(banner string, versionInfo map[string]string) Result {
	r.VersionInfo = versionInfo
	r.Banner = banner
	r.Status = OnlySSL
	return *r
}

func (r *Result) notMatched(banner string) Result {
	r.Banner = banner
	r.Status = Matched
	return *r
}

func (r *Result) matched(banner string, versionInfo map[string]string) Result {
	r.VersionInfo = versionInfo
	r.Banner = banner
	r.Status = Matched

	if r.IsSSL == true {
		switch r.Service() {
		case "http":
			r.VersionInfo["service"] = "https"
		}
	}
	return *r
}
