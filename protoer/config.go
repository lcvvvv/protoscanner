package protoer

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"time"
)

var defaultConfig Config

//go:embed nmap.json
var fileNmapJson embed.FS

func init() {
	buf, err := fileNmapJson.ReadFile("nmap.json")
	if err != nil {
		panic(err)
	}
	defaultConfig, err = ParseConfig(buf)
	if err != nil {
		panic(err)
	}
}

type Config struct {
	Probes  []Probe `json:"probes"`   //探针清单
	Matches []Match `json:"matchers"` //指纹清单

	UDPHighProbes map[int][]string `json:"udp_high_probes"` // map[port][]Probe.Name 按顺序存储优先级最高的ProbeName
	TCPHighProbes map[int][]string `json:"tcp_high_probes"` // map[port][]Probe.Name 按顺序存储优先级最高的ProbeName
}

func ParseConfig(buf []byte) (Config, error) {
	var cfg = Config{}
	err := json.Unmarshal(buf, &cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

type ScanConfig struct {
	FullProbeMode bool //是否尝试对目标发送所有探针

	ReadTimeout time.Duration //读取响应的超时时间
	DialTimeout time.Duration //连接端口的超时时间

	ResponseSize int //获取返回包的最大长度
}

var defaultScanConfig = ScanConfig{
	FullProbeMode: false,
	ReadTimeout:   3000 * time.Millisecond,
	DialTimeout:   1500 * time.Millisecond,
	ResponseSize:  1024 * 10,
}

type Regexp struct {
	*regexp.Regexp
}

func (r *Regexp) UnmarshalJSON(b []byte) error {
	var pattern string
	if err := json.Unmarshal(b, &pattern); err != nil {
		return err
	}
	raw, err := base64.StdEncoding.DecodeString(pattern)
	if err != nil {
		return err
	}

	regx, err := regexp.Compile(string(raw))
	if err != nil {
		return err
	}
	r.Regexp = regx
	return nil
}

func (r *Regexp) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString([]byte(r.String())))
}

func getScanConfig(cfgs ...ScanConfig) ScanConfig {
	if len(cfgs) > 0 {
		return cfgs[0]
	} else {
		return defaultScanConfig
	}
}

func getConfig(cfgs ...Config) Config {
	if len(cfgs) > 0 {
		return cfgs[0]
	} else {
		return defaultConfig
	}
}

func NewScanConfig() ScanConfig {
	return defaultScanConfig
}

func DefaultConfig() Config {
	return defaultConfig
}
