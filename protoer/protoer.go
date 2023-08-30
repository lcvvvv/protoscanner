package protoer

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/lcvvvv/ranger"
	"net"
	"sort"
	"strconv"
	"time"
)

type Status int

const (
	// Closed 关闭
	Closed Status = 1 << iota
	// Opened 端口开放，但是没有任何回应信息
	Opened
	// NotMatched 端口开放，有返回包，但是无法识别协议类型
	NotMatched
	// OnlySSL 端口开放，协议为SSL，除此之外无其他信息
	OnlySSL
	// Matched 端口开放，已准确识别协议
	Matched
)

func (s Status) String() string {
	switch s {
	case Closed:
		return "Closed"
	case Opened:
		return "Opened"
	case NotMatched:
		return "NotMatched"
	case OnlySSL:
		return "OnlySSL"
	case Matched:
		return "Matched"
	default:
		return "Closed"
	}
}

type Protoer struct {
	udpHighProbes map[int][]string // map[port][]Probe.Name 按顺序存储UDP协议优先级最高的ProbeName
	tcpHighProbes map[int][]string // map[port][]Probe.Name 按顺序存储TCP协议优先级最高的ProbeName

	sslPortSecondProbes *ranger.Ranger[string] // []Probe.Name，对SSL协议进行二次检测的探针
	fullPortProbes      *ranger.Ranger[string] // []Probe.Name，适用于全端口的探针名称
	sslPortProbes       *ranger.Ranger[string] // []Probe.Name，用于检测端口协议是否为SSL的探针名称

	probeMap map[string]Probe // map[Probe.Name]*Probe
	matchMap map[string]Match // map[Match.Name]*Match

	udpPortMap map[int][]string // map[Port][]Probe.Name
	tcpPortMap map[int][]string // map[Port][]Probe.Name

	dialContextFn    func(ctx context.Context, network, addr string) (net.Conn, error)
	dialTLSContextFn func(ctx context.Context, network, address string) (*tls.Conn, error)
}

func New(cfgs ...Config) *Protoer {
	cfg := getConfig(cfgs...)
	proto := &Protoer{
		udpHighProbes: cfg.UDPHighProbes,
		tcpHighProbes: cfg.TCPHighProbes,

		sslPortSecondProbes: ranger.New[string](),
		fullPortProbes:      ranger.New[string](),
		sslPortProbes:       ranger.New[string](),

		probeMap: map[string]Probe{},
		matchMap: map[string]Match{},

		udpPortMap: map[int][]string{},
		tcpPortMap: map[int][]string{},
	}

	//初始化数据

	for i := 1; i <= 65535; i++ {
		proto.udpPortMap[i] = []string{}
		proto.tcpPortMap[i] = []string{}
	}

	for _, p := range cfg.Probes {
		proto.probeMap[p.Name] = p

		if p.IsSSLPorts {
			proto.sslPortSecondProbes.Push(p.Name)
		}

		if p.IsAllPorts {
			proto.fullPortProbes.Push(p.Name)
		}

		if p.IsIdentifySSL {
			proto.sslPortProbes.Push(p.Name)
		}

		for _, num := range p.Ports.Value() {
			if p.Network == "tcp" {
				proto.tcpPortMap[num] = append(proto.tcpPortMap[num], p.Name)
			} else {
				proto.udpPortMap[num] = append(proto.udpPortMap[num], p.Name)
			}
		}

		for _, num := range p.SSLPorts.Value() {
			if p.Network == "tcp" {
				proto.tcpPortMap[num] = append(proto.tcpPortMap[num], p.Name)
			} else {
				proto.udpPortMap[num] = append(proto.udpPortMap[num], p.Name)
			}
		}

	}

	for _, m := range cfg.Matches {
		proto.matchMap[m.Name] = m
	}

	proto.SetDialContextFn((&net.Dialer{}).DialContext)

	//排序阶段
	proto.sslPortProbes.Sort(proto.getRarity)
	proto.fullPortProbes.Sort(proto.getRarity)
	proto.sslPortSecondProbes.Sort(proto.getRarity)

	for num := 1; num <= 65535; num++ {
		sort.Slice(proto.tcpPortMap[num], func(i, j int) bool {
			return proto.getRarity(proto.tcpPortMap[num][i]) < proto.getRarity(proto.tcpPortMap[num][j])
		})
		sort.Slice(proto.udpPortMap[num], func(i, j int) bool {
			return proto.getRarity(proto.udpPortMap[num][i]) < proto.getRarity(proto.udpPortMap[num][j])
		})
	}

	return proto
}

var (
	errorsConnectFailed    = errors.New("CONNECT_FAILED")
	errorsTLSConnectFailed = errors.New("TLS_CONNECT_FAILED")
)

func (p *Protoer) SetDialContextFn(fn func(ctx context.Context, network, address string) (net.Conn, error)) {
	p.dialContextFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := fn(ctx, network, addr)
		if err != nil {
			err = errors.Join(err, errorsConnectFailed)
		}
		return conn, err
	}

	p.dialTLSContextFn = func(ctx context.Context, network, address string) (*tls.Conn, error) {
		tcpConn, err := p.dialContextFn(ctx, network, address)
		if err != nil {
			return nil, err
		}
		// 增加TLS握手超时限制
		tcpConn.SetDeadline(time.Now().Add(3 * time.Second))
		conn := tls.Client(tcpConn, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
		})
		err = conn.Handshake()
		if err != nil {
			conn.Close()
			err = errors.Join(err, errorsTLSConnectFailed)
			return nil, err
		}
		// 取消超时设置
		tcpConn.SetReadDeadline(time.Time{})
		return conn, err
	}

}

func (p *Protoer) Identify(network string, addr net.IP, port int, scanConfigs ...ScanConfig) *Results {
	var scanConfig = getScanConfig(scanConfigs...)
	var probeNames = ranger.New[string]()
	var results = &Results{
		list:    []Result{},
		scanned: ranger.New[string](),
	}
	switch network {
	case "tcp":
		if names, ok := p.tcpHighProbes[port]; ok {
			//如果存在优先级较高的探针，则优先扫描这类探针
			probeNames.Push(names...)
		}

		//默认优先扫描全端口探针
		probeNames.Push(p.fullPortProbes.Value()...)
		//扫描端口特定探针
		probeNames.Push(p.tcpPortMap[port]...)
		//扫描SSL协议检测探针
		probeNames.Push(p.sslPortProbes.Value()...)

		if scanConfig.FullProbeMode {
			//压入全部探针作为待扫描队列
			for _, probe := range p.probeMap {
				if probe.Network == "tcp" {
					probeNames.Push(probe.Name)
				}
			}
		}

		p.identify(addr, port, results, scanConfig, probeNames.Value()...)
		if results.Status() != OnlySSL {
			return results
		}

		for _, name := range p.sslPortSecondProbes.Value() {
			result := p.identifyByProbe(addr, port, true, p.getProbe(name), scanConfig)
			results.push(result)
			if result.Status == Matched {
				return results
			}
		}
		return results
	case "udp":
		if names, ok := p.udpHighProbes[port]; ok {
			//如果存在优先级较高的探针，则优先扫描这类探针
			probeNames.Push(names...)
		}

		if scanConfig.FullProbeMode {
			//压入全部探针作为待扫描队列
			for _, probe := range p.probeMap {
				if probe.Network == "udp" {
					probeNames.Push(probe.Name)
				}
			}
		}

		probeNames.Push(p.udpPortMap[port]...)
		p.identify(addr, port, results, scanConfig, probeNames.Value()...)
		return results
	default:
		panic(errors.New("invalid network:" + network))
	}
}

func (p *Protoer) IdentifyByProbe(addr net.IP, port int, isSSL bool, probeName string, scanConfigs ...ScanConfig) Result {
	return p.identifyByProbe(addr, port, isSSL, p.getProbe(probeName), getScanConfig(scanConfigs...))
}

func (p *Protoer) identify(addr net.IP, port int, r *Results, config ScanConfig, probeNames ...string) {
	for _, probeName := range probeNames {
		probe := p.getProbe(probeName)

		// TCP方式进行协议识别
		if probe.Ports.Contains(port) || (!probe.Ports.Contains(port) && !probe.SSLPorts.Contains(port)) {
			if r.isScanned(probeName, false) {
				//如果已经扫描过，则跳过
				continue
			}
			result := p.identifyByProbe(addr, port, false, probe, config)
			//fmt.Println(result.ProbeName, result.Status, result.Banner, result.errMsg)
			r.push(result)
			if result.Status == OnlySSL || result.Status == Matched || result.Status == Closed {
				return
			}
		}

		// SSL方式进行协议识别
		if probe.SSLPorts.Contains(port) {
			result := p.identifyByProbe(addr, port, true, probe, config)
			r.push(result)
			//fmt.Println(result.ProbeName, result.Status, result.Banner, result.errMsg)
			if errors.Is(&result, errorsTLSConnectFailed) && !r.isScanned(probeName, false) {
				//如果是在建立连接阶段失败，并且TCP方式没有扫描过，将尝试使用TCP方式测试一遍
				result = p.identifyByProbe(addr, port, false, probe, config)
				r.push(result)
			}

			if result.Status == OnlySSL || result.Status == Matched || result.Status == Closed {
				return
			}
		}
	}
}

func (p *Protoer) identifyByProbe(addr net.IP, port int, isSSL bool, probe Probe, cfg ScanConfig) (r Result) {
	defer r.statTime()()

	address := net.JoinHostPort(addr.String(), strconv.Itoa(port))
	//加载请求数据到Result
	r.loadProbe(address, probe, isSSL)

	var conn net.Conn
	var err error
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()
	if isSSL {
		conn, err = p.dialTLSContextFn(ctx, probe.Network, address)
		if err != nil && errors.Is(err, errorsTLSConnectFailed) {
			return r.opened(err)
		} else {
			r.loadTLSState(conn.(*tls.Conn).ConnectionState())
		}
	} else {
		conn, err = p.dialContextFn(ctx, probe.Network, address)
	}
	if err != nil {
		return r.closed(err)
	}

	var banner string
	banner, err = probe.SendProbeWithNetConn(conn, cfg.ReadTimeout, cfg.ResponseSize)
	if err != nil {
		//若无法获取Banner直接返回失败
		return r.opened(err)
	}

	for _, matchName := range probe.MatcherNames {
		m := p.getMatch(matchName)
		if versionInfo, ok := m.MatchString(banner); ok {
			if versionInfo["service"] == "ssl" {
				return r.onlySSL(banner, versionInfo)
			} else {
				return r.matched(banner, versionInfo)
			}
		}
	}

	return r.notMatched(banner)
}

func (p *Protoer) getRarity(probeName string) int {
	return p.getProbe(probeName).Rarity
}

func (p *Protoer) getProbe(probeName string) Probe {
	return p.probeMap[probeName]
}

func (p *Protoer) getMatch(matchName string) Match {
	return p.matchMap[matchName]
}
