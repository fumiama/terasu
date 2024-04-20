package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/fumiama/terasu"
	"github.com/fumiama/terasu/ip"
)

func TestResolver(t *testing.T) {
	t.Log("IsIPv6Available:", ip.IsIPv6Available.Get())
	addrs, err := DefaultResolver.LookupHost(context.TODO(), "huggingface.co")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(addrs)
	if len(addrs) == 0 {
		t.Fail()
	}
}

func TestDNS(t *testing.T) {
	if ip.IsIPv6Available.Get() {
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
	dotv6serversbak := IPv6Servers.m
	dotv4serversbak := IPv4Servers.m
	defer func() {
		IPv6Servers.m = dotv6serversbak
		IPv4Servers.m = dotv4serversbak
	}()
	if ip.IsIPv6Available.Get() {
		IPv6Servers = DNSList{
			m: map[string][]*dnsstat{},
		}
		IPv6Servers.Add(&DNSConfig{
			Servers: map[string][]string{"test.bad.host": {"169.254.122.111"}},
		})
	} else {
		IPv4Servers = DNSList{
			m: map[string][]*dnsstat{},
		}
		IPv4Servers.Add(&DNSConfig{
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

func (ds *DNSList) test() {
	ds.RLock()
	defer ds.RUnlock()
	for host, addrs := range ds.m {
		for _, addr := range addrs {
			if !addr.E {
				continue
			}
			fmt.Println("dial:", host, addr.A)
			conn, err := net.Dial("tcp", addr.A)
			if err != nil {
				continue
			}
			tlsConn := tls.Client(conn, &tls.Config{ServerName: host})
			err = terasu.Use(tlsConn).Handshake(4)
			_ = tlsConn.Close()
			if err == nil {
				fmt.Println("succ:", host, addr.A)
				continue
			}
			fmt.Println("fail:", host, addr.A)
		}
	}
}
