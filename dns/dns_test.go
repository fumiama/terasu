package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/fumiama/terasu"
	"github.com/fumiama/terasu/dialer"
	"github.com/fumiama/terasu/ip"
)

func TestResolver(t *testing.T) {
	t.Log("IsIPv6Available:", ip.IsIPv6Available)
	addrs, err := DefaultResolver.LookupHost(context.TODO(), "huggingface.co")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(addrs)
	if len(addrs) == 0 {
		t.Fail()
	}
}

func TestResolverFallback(t *testing.T) {
	t.Log("IsIPv6Available:", ip.IsIPv6Available)

	if ip.IsIPv6Available {
		addrs, err := IPv6Servers.lookupHostDoH(context.TODO(), "huggingface.co")
		if err != nil {
			t.Fatal(err)
		}
		t.Log(addrs)
		if len(addrs) == 0 {
			t.Fail()
		}
	}
	addrs, err := IPv4Servers.lookupHostDoH(context.TODO(), "huggingface.co")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(addrs)
	if len(addrs) == 0 {
		t.Fail()
	}
}

func TestDNS(t *testing.T) {
	if ip.IsIPv6Available {
		IPv6Servers.test()
	}
	IPv4Servers.test()
	for i := 0; i < 10; i++ {
		addrs, err := DefaultResolver.LookupHost(context.TODO(), "huggingface.co")
		if err != nil {
			t.Fatal(err)
		}
		t.Log(addrs)
		if len(addrs) == 0 {
			t.Fail()
		}
		time.Sleep(time.Millisecond * 50)
	}
}

func TestBadDNS(t *testing.T) {
	dotv6serversseqbak := IPv6Servers.hostseq
	dotv4serversseqbak := IPv4Servers.hostseq
	dotv6serversbak := IPv6Servers.m
	dotv4serversbak := IPv4Servers.m
	defer func() {
		IPv6Servers.hostseq = dotv6serversseqbak
		IPv4Servers.hostseq = dotv4serversseqbak
		IPv6Servers.m = dotv6serversbak
		IPv4Servers.m = dotv4serversbak
	}()
	if ip.IsIPv6Available {
		IPv6Servers = List{
			m: map[string][]*dnsstat{},
		}
		IPv6Servers.Add(&Config{
			Servers: map[string][]string{"test.bad.host": {"169.254.122.111"}},
		})
	} else {
		IPv4Servers = List{
			m: map[string][]*dnsstat{},
		}
		IPv4Servers.Add(&Config{
			Servers: map[string][]string{"test.bad.host": {"169.254.122.111:853"}},
		})
	}
	for i := 0; i < 10; i++ {
		addrs, err := DefaultResolver.LookupHost(context.TODO(), "api.mangacopy.com")
		t.Log(err)
		if err == nil && len(addrs) > 0 {
			t.Fatal("unexpected")
		}
		time.Sleep(time.Millisecond * 50)
	}
}

func (ds *List) test() {
	ds.RLock()
	defer ds.RUnlock()
	_ = ds.rangeHosts(func(host string, addrs []*dnsstat) error {
		for _, addr := range addrs {
			if !addr.enabled() {
				continue
			}
			fmt.Println("dial:", host, addr.addr)
			conn, err := dialer.DefaultDialer.Dial("tcp", addr.addr)
			if err != nil {
				continue
			}
			tlsConn := tls.Client(terasu.NewConn(conn), &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS12,
			})
			err = tlsConn.Handshake()
			_ = tlsConn.Close()
			if err == nil {
				fmt.Println("succ:", host, addr.addr)
				continue
			}
			fmt.Println("fail:", host, addr.addr)
		}
		return nil
	})
}
