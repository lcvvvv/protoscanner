package protoer

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestJsonSSSS(t *testing.T) {
	raw := `{"name":"TCP_NULL","rarity":0,"is_full_port":true,"is_ssl_port":false,"ports":null,"ssl_ports":null,"network":"TCP","data":"","matcher_names":["TCP_NULL_Matcher"]}`
	var p = Probe{}
	err := json.Unmarshal([]byte(raw), &p)
	fmt.Println(err, p)
}
