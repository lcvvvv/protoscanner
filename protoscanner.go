package protoscanner

import (
	"github.com/lcvvvv/pool"
	"github.com/lcvvvv/protoscanner/protoer"
	"net"
)

type Client struct {
	*pool.Scheduler

	scanner *protoer.Protoer

	Config Config
}

type Config struct {
	//protoer引擎配置文件
	protoConfig protoer.Config
	//protoer单次扫描的默认配置文件
	protoScanConfig protoer.ScanConfig
	//并发数
	Threads int
}

type Configure func(*Config)

var defaultConfig = Config{
	protoConfig: protoer.DefaultConfig(),

	protoScanConfig: protoer.NewScanConfig(),

	Threads: 400,
}

func New(cfgs ...Configure) *Client {
	var cli = &Client{
		Config: defaultConfig,
	}

	cli.Configure(cfgs...)

	cli.scanner = protoer.New(cli.Config.protoConfig)

	p := pool.New(cli.Config.Threads, func(token string, i ...any) any {
		scanConfig := cli.Config.protoScanConfig
		network := i[0].(string)
		addr := i[1].(net.IP)
		port := i[2].(int)
		scanConfig = i[3].(protoer.ScanConfig)
		return cli.scanner.Identify(network, addr, port, scanConfig)
	})

	cli.Scheduler = pool.NewScheduler(p)
	return cli
}

func (c *Client) Configure(cfgs ...Configure) {
	for _, configure := range cfgs {
		configure(&c.Config)
	}
}

func NewParams(network string, addr net.IP, port int, scanConfig protoer.ScanConfig) pool.Params {
	return pool.NewParams(network, addr, port, scanConfig)
}

func ParseOutput(output any) *protoer.Results {
	return output.(*protoer.Results)
}

func ParseParams(params pool.Params) (network string, addr net.IP, port int, scanConfigs protoer.ScanConfig) {
	return params[0].(string), params[1].(net.IP), params[2].(int), params[3].(protoer.ScanConfig)
}
