package protoer

import (
	"fmt"
	"net"
	"testing"
)

func TestProtoer_Scan(t *testing.T) {
	var p = New()
	r := p.Identify("tcp", net.ParseIP("127.0.0.1"), 8080)
	fmt.Println(r.Service(), r.Status(), r.Value().VersionInfo)
}
