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
			"www.whatsapp.com": {"57.144.245.32"},
		},
	})
	resp, err := Get("https://www.whatsapp.com/")
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
