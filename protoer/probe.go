package protoer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/lcvvvv/ranger"
	"io"
	"net"
	"time"
)

var errorsResponseIsEmpty = errors.New("response is empty")

type Probe struct {
	Name   string `json:"name"`   //探针名称
	Rarity int    `json:"rarity"` //探针级别

	IsAllPorts    bool `json:"is_full_port"`    //是否适用于全端口
	IsSSLPorts    bool `json:"is_ssl_port"`     //是否适用于SSL端口，主要针对于识别出是SSL，但无法识别出其准确协议的端口进行二次检测
	IsIdentifySSL bool `json:"is_identify_ssl"` //是否可以用于识别端口是否是SSL协议

	Ports    *ranger.Ranger[int] `json:"ports"`     //探针适用默认端口号
	SSLPorts *ranger.Ranger[int] `json:"ssl_ports"` //探针适用SSL端口号

	Network      string   `json:"network"`       //探针发送的协议类型 tcp、udp等
	Data         Raw      `json:"data"`          //探针发送出去的数据
	MatcherNames []string `json:"matcher_names"` //检测结果可匹配的MatcherName
}

type Raw struct {
	Value string
}

func (r *Raw) UnmarshalJSON(b []byte) error {
	var pattern string
	if err := json.Unmarshal(b, &pattern); err != nil {
		return err
	}
	value, err := base64.StdEncoding.DecodeString(pattern)
	if err != nil {
		return err
	}
	r.Value = string(value)
	return nil
}

func (r *Raw) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString([]byte(r.Value)))
}

func (p *Probe) SendProbeWithNetConn(conn net.Conn, timeout time.Duration, size int) (response string, err error) {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err = conn.Write(p.GetProbeData(conn.RemoteAddr().Network(), conn.RemoteAddr().String()))
	if err != nil {
		return "", err
	}

	//读取数据
	var buf []byte              // big buffer
	var tmp = make([]byte, 256) // using small tmo buffer for demonstrating
	var length int
	for {
		//设置读取超时Deadline
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		length, err = conn.Read(tmp)
		buf = append(buf, tmp[:length]...)
		if length < len(tmp) {
			break
		}
		if err != nil {
			break
		}
		if len(buf) > size {
			break
		}
	}

	if err != nil && err != io.EOF {
		return "", err
	}

	if len(buf) == 0 {
		return "", errorsResponseIsEmpty
	}

	return string(buf), nil
}

var (
	keywordHost    = []byte("{Host}")
	keywordNetwork = []byte("{Network}")
)

func (p *Probe) GetProbeData(network, address string) []byte {
	data := []byte(p.Data.Value)
	data = bytes.ReplaceAll(data, keywordHost, []byte(address))
	data = bytes.ReplaceAll(data, keywordNetwork, []byte(network))
	return data
}
