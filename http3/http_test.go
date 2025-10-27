package http3

import (
	"io"
	"testing"

	"github.com/fumiama/terasu/dns"
)

func TestClientGet(t *testing.T) {
	dns.IPv4Servers = *dns.NewEmptyList()
	dns.IPv6Servers = *dns.NewEmptyList()
	dns.IPv4Servers.Add(&dns.Config{
		Fallbacks: map[string][]string{
			"huggingface.co": {"52.222.136.117"},
		},
	})
	resp, err := Get("https://huggingface.co/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	t.Log("[T] response code", resp.StatusCode)
	for k, vs := range resp.Header {
		for _, v := range vs {
			t.Log("[T] response header", k+":", v)
		}
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fail()
	}
	t.Log(string(data))
}
