package protoscanner

import (
	"fmt"
	"github.com/lcvvvv/pool"
	"github.com/lcvvvv/protoscanner/protoer"
	"net"
	"testing"
)

func TestNew(t *testing.T) {
	cli := New()
	go cli.Pool.Run()

	outputs := cli.RunMultipleJobs(65535, func(paramsCh chan<- pool.Params) {
		for port := 1; port <= 65535; port++ {
			paramsCh <- NewParams("tcp", net.ParseIP("127.0.0.1"), port, cli.Config.protoScanConfig)
		}
	})

	for _, output := range outputs {
		network, addr, port, _ := ParseParams(output.Params)
		results := ParseOutput(output.Result)
		result := results.Value()
		switch results.Status() {
		case protoer.Closed:
			// 跳过
		case protoer.Opened:
			fmt.Println(fmt.Sprintf("%s://%s:%d is Opened", network, addr.String(), port))
		case protoer.NotMatched:
			// 跳过
		case protoer.OnlySSL:
			fmt.Println(fmt.Sprintf("%s://%s:%d is OnlySSL,cert: %v", network, addr.String(), port, result.TLSState))
		case protoer.Matched:
			fmt.Println(fmt.Sprintf("%s://%s:%d is Matched %v %v", network, addr.String(), port, result.Service(), result.VersionInfo))
		}
	}
}
