package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/fumiama/terasu"
	"github.com/fumiama/terasu/ip"
)

var (
	ErrNoDNSAvailable = errors.New("no dns available")
)

var DefaultDialer = net.Dialer{
	Timeout: time.Second * 8,
}

type dnsstat struct {
	A string
	E bool
}

type DNSList struct {
	sync.RWMutex
	m map[string][]*dnsstat
	b map[string][]string
}

type DNSConfig struct {
	Servers   map[string][]string // Servers map[dot.com]ip:ports
	Fallbacks map[string][]string // Fallbacks map[domain]ips
}

// hasrecord no lock, use under lock
func hasrecord(lst []*dnsstat, a string) bool {
	for _, addr := range lst {
		if addr.A == a {
			return true
		}
	}
	return false
}

// hasrecord no lock, use under lock
func hasfallback(lst []string, a string) bool {
	for _, addr := range lst {
		if addr == a {
			return true
		}
	}
	return false
}

func (ds *DNSList) Add(c *DNSConfig) {
	ds.Lock()
	defer ds.Unlock()
	addList := map[string][]*dnsstat{}
	for host, addrs := range c.Servers {
		for _, addr := range addrs {
			if !hasrecord(ds.m[host], addr) && !hasrecord(addList[host], addr) {
				addList[host] = append(addList[host], &dnsstat{addr, true})
			}
		}
	}
	for host, addrs := range addList {
		ds.m[host] = append(ds.m[host], addrs...)
	}
	addListFallback := map[string][]string{}
	for host, addrs := range c.Fallbacks {
		for _, addr := range addrs {
			if !hasfallback(ds.b[host], addr) && !hasfallback(addListFallback[host], addr) {
				addListFallback[host] = append(addListFallback[host], addr)
			}
		}
	}
	for host, addrs := range addListFallback {
		ds.b[host] = append(ds.b[host], addrs...)
	}
}

func (ds *DNSList) LookupHostFallback(ctx context.Context, host string) ([]string, error) {
	ds.RLock()
	defer ds.RUnlock()
	if addrs, ok := ds.b[host]; ok {
		return addrs, nil
	}
	return net.DefaultResolver.LookupHost(ctx, host)
}

func (ds *DNSList) DialContext(ctx context.Context, dialer *net.Dialer, firstFragmentLen uint8) (tlsConn *tls.Conn, err error) {
	err = ErrNoDNSAvailable

	if dialer == nil {
		dialer = &DefaultDialer
	}

	ds.RLock()
	defer ds.RUnlock()

	if dialer.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dialer.Timeout)
		defer cancel()
	}

	if !dialer.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, dialer.Deadline)
		defer cancel()
	}

	var conn net.Conn
	for host, addrs := range ds.m {
		for _, addr := range addrs {
			if !addr.E {
				continue
			}
			conn, err = dialer.DialContext(ctx, "tcp", addr.A)
			if err != nil {
				addr.E = false // no need to acquire write lock
				continue
			}
			tlsConn = tls.Client(conn, &tls.Config{ServerName: host})
			err = terasu.Use(tlsConn).HandshakeContext(ctx, firstFragmentLen)
			if err == nil {
				return
			}
			_ = tlsConn.Close()
			addr.E = false // no need to acquire write lock
		}
	}
	return
}

var IPv6Servers = DNSList{
	m: map[string][]*dnsstat{
		"dot.sb": {
			{"[2a09::]:853", true},
			{"[2a11::]:853", true},
		},
		"dns.google": {
			{"[2001:4860:4860::8888]:853", true},
			{"[2001:4860:4860::8844]:853", true},
		},
		"cloudflare-dns.com": {
			{"[2606:4700:4700::1111]:853", true},
			{"[2606:4700:4700::1001]:853", true},
		},
		"dns.opendns.com": {
			{"[2620:119:35::35]:853", true},
			{"[2620:119:53::53]:853", true},
		},
		"dns10.quad9.net": {
			{"[2620:fe::10]:853", true},
			{"[2620:fe::fe:10]:853", true},
		},
	},
	b: map[string][]string{},
}

var IPv4Servers = DNSList{
	m: map[string][]*dnsstat{
		"dot.sb": {
			{"185.222.222.222:853", true},
			{"45.11.45.11:853", true},
		},
		"dns.google": {
			{"8.8.8.8:853", true},
			{"8.8.4.4:853", true},
		},
		"cloudflare-dns.com": {
			{"1.1.1.1:853", true},
			{"1.0.0.1:853", true},
		},
		"dns.opendns.com": {
			{"208.67.222.222:853", true},
			{"208.67.220.220:853", true},
		},
		"dns10.quad9.net": {
			{"9.9.9.10:853", true},
			{"149.112.112.10:853", true},
		},
	},
	b: map[string][]string{},
}

var DefaultResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		if ip.IsIPv6Available.Get() {
			return IPv6Servers.DialContext(ctx, nil, terasu.DefaultFirstFragmentLen)
		}
		return IPv4Servers.DialContext(ctx, nil, terasu.DefaultFirstFragmentLen)
	},
}
