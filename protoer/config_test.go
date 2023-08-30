package protoer

import (
	"encoding/json"
	"log"
	"os"
	"testing"
)

func TestUnmarshalConfig(t *testing.T) {

	path := "/Users/kv2/Desktop/nmap.json"
	buf, err := os.ReadFile(path)
	if err != nil {
		log.Fatalln(err)
	}
	var config Config
	err = json.Unmarshal(buf, &config)
	if err != nil {
		log.Fatalln(err)
	}
}
