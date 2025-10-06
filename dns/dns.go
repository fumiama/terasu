package dns

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fumiama/terasu"
	"github.com/fumiama/terasu/ip"
	"github.com/sirupsen/logrus"
)

var (
	// ErrNoDNSAvailable is reported when all servers failed to response
	ErrNoDNSAvailable = errors.New("no dns available")
	// ErrSuccess is designed for range hosts to break
	ErrSuccess = errors.New("success")
)

var dnsDialer = net.Dialer{
	Timeout: time.Second * 4,
}

func SetTimeout(t time.Duration) {
	dnsDialer.Timeout = t
}

type dnsstat struct {
	addr string
	en   bool
	keep bool
}

func (ds *dnsstat) String() string {
	sb := strings.Builder{}
	sb.WriteString("[addr: ")
	sb.WriteString(ds.addr)
	sb.WriteString(", enable: ")
	if ds.en {
		sb.WriteString("true, keep: ")
	} else {
		sb.WriteString("false, keep: ")
	}
	if ds.keep {
		sb.WriteString("true]")
	} else {
		sb.WriteString("false]")
	}
	return sb.String()
}

func (ds *dnsstat) ishttps() bool {
	return strings.HasPrefix(ds.addr, "https://")
}

func (ds *dnsstat) keepit() {
	ds.keep = true
}

func (ds *dnsstat) enabled() bool {
	return ds.keep || ds.en
}

func (ds *dnsstat) disable(reEnable time.Duration) {
	if ds.keep {
		return
	}
	ds.en = false
	// re-enable after some times
	time.AfterFunc(reEnable, func() {
		ds.en = true
	})
}

type DNSList struct {
	sync.RWMutex
	hostseq []string
	m       map[string][]*dnsstat
	b       map[string][]string
}

type DNSConfig struct {
	Servers   map[string][]string `yaml:"Servers"`   // Servers map[dot.com]ip:ports
	Fallbacks map[string][]string `yaml:"Fallbacks"` // Fallbacks map[domain]ips
}

// hasrecord no lock, use under lock
func hasrecord(lst []*dnsstat, a string) bool {
	for _, addr := range lst {
		if addr.addr == a {
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
	addHosts := map[string]struct{}{}
	for host, addrs := range c.Servers {
		availableHosts, ok := ds.m[host]
		if !ok {
			addHosts[host] = struct{}{}
		}
		for _, addr := range addrs {
			if !hasrecord(availableHosts, addr) && !hasrecord(addList[host], addr) {
				addList[host] = append(addList[host], &dnsstat{addr, true, false})
			}
		}
	}
	for host, addrs := range addList {
		ds.m[host] = append(ds.m[host], addrs...)
	}
	for host := range addHosts {
		ds.hostseq = append(ds.hostseq, host)
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

// rangeHosts in sequence, please use in rlock
func (ds *DNSList) rangeHosts(fn func(host string, addrs []*dnsstat) error) error {
	for _, h := range ds.hostseq {
		if err := fn(h, ds.m[h]); err != nil {
			return err
		}
	}
	return nil
}

func (ds *DNSList) lookupHostDoH(ctx context.Context, host string) (hosts []string, err error) {
	ds.RLock()
	defer ds.RUnlock()
	// try to use DoH first
	err = ds.rangeHosts(func(_ string, addrs []*dnsstat) error {
		for _, addr := range addrs {
			if !addr.enabled() || !addr.ishttps() { // disabled or is not DoH
				continue
			}
			jr, err := lookupdoh(ctx, addr.addr, host)
			if err == nil {
				hosts = jr.hosts()
				if len(hosts) > 0 {
					// this is a successful server, keep it
					addr.keepit()
					return ErrSuccess
				}
			}
			if !errors.Is(err, context.Canceled) &&
				!errors.Is(err, syscall.ENETUNREACH) &&
				!errors.Is(err, syscall.ENETDOWN) {
				addr.disable(time.Hour) // no need to acquire write lock
			}
		}
		return nil // not found, fallback to ds.b
	})
	if errors.Is(err, ErrSuccess) {
		err = nil
	}
	if len(hosts) > 0 || err != nil {
		return
	}
	if addrs, ok := ds.b[host]; ok {
		return addrs, nil
	}
	return nil, ErrNoDNSAvailable
}

func (ds *DNSList) DialContext(ctx context.Context, dialer *net.Dialer, firstFragmentLen uint8) (tlsConn *tls.Conn, err error) {
	err = ErrNoDNSAvailable

	if dialer == nil {
		dialer = &dnsDialer
	}

	ds.RLock()
	defer ds.RUnlock()

	var conn net.Conn
	_ = ds.rangeHosts(func(host string, addrs []*dnsstat) error {
		for _, addr := range addrs {
			if !addr.enabled() || addr.ishttps() { // disabled or is DoH
				continue
			}
			logrus.Debugln("[terasu.dns] -> dial", host, addr)
			if dialer.Timeout != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(context.Background(), dialer.Timeout)
				defer cancel()
			} else if !dialer.Deadline.IsZero() {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(context.Background(), dialer.Deadline)
				defer cancel()
			}
			conn, err = dialer.DialContext(ctx, "tcp", addr.addr)
			if err != nil {
				logrus.Debugln("[terasu.dns] -- dial tcp", host, addr, "err:", err)
				if !errors.Is(err, context.Canceled) &&
					!errors.Is(err, syscall.ENETUNREACH) &&
					!errors.Is(err, syscall.ENETDOWN) {
					addr.disable(time.Hour) // no need to acquire write lock
				}
				continue
			}
			logrus.Debugln("[terasu.dns] <- dial tcp", host, addr, "succeeded")
			logrus.Debugln("[terasu.dns] -> hs tls", host, addr)
			tlsConn = tls.Client(conn, &tls.Config{
				ServerName: host,
				MinVersion: tls.VersionTLS12,
				NextProtos: []string{"dns"},
			})
			// re-init ctx due to deadline settings in tcp dial
			if dialer.Timeout != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(context.Background(), dialer.Timeout)
				defer cancel()
			} else if !dialer.Deadline.IsZero() {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(context.Background(), dialer.Deadline)
				defer cancel()
			}
			if firstFragmentLen > 0 {
				logrus.Debugln("[terasu.dns] -- hs tls", host, addr, "use first frag len", firstFragmentLen)
				err = terasu.Use(tlsConn).HandshakeContext(ctx, firstFragmentLen)
			} else {
				logrus.Debugln("[terasu.dns] -- hs tls", host, addr, "normally")
				err = tlsConn.HandshakeContext(ctx)
			}
			if err == nil {
				logrus.Debugln("[terasu.dns] <- hs tls", host, addr, "succeeded")
				// this is a successful server, keep it
				addr.keepit()
				return ErrSuccess
			}
			logrus.Debugln("[terasu.dns] -- hs tls", host, addr, "err:", err)
			_ = tlsConn.Close()
			if !errors.Is(err, context.Canceled) &&
				!errors.Is(err, syscall.ENETUNREACH) &&
				!errors.Is(err, syscall.ENETDOWN) {
				logrus.Debugln("[terasu.dns] == disable", host, addr)
				addr.disable(time.Hour) // no need to acquire write lock
			}
		}
		return nil
	})
	return
}

var IPv6Servers = DNSList{
	hostseq: []string{
		"dot.sb", "dns.google", "cloudflare-dns.com", "dns.opendns.com", "dns10.quad9.net",
	},
	m: map[string][]*dnsstat{
		"dot.sb": {
			{"[2a09::]:853", true, false},
			{"[2a11::]:853", true, false},
			{"https://doh.sb/dns-query", true, false},
		},
		"dns.google": {
			{"[2001:4860:4860::8888]:853", true, false},
			{"[2001:4860:4860::8844]:853", true, false},
			{"https://dns.google/resolve", true, false},
			{"https://[2001:4860:4860::8888]/resolve", true, false},
			{"https://[2001:4860:4860::8844]/resolve", true, false},
		},
		"cloudflare-dns.com": {
			{"[2606:4700:4700::1111]:853", true, false},
			{"[2606:4700:4700::1001]:853", true, false},
			{"https://cloudflare-dns.com/dns-query", true, false},
			{"https://[2606:4700:4700::1111]/dns-query", true, false},
			{"https://[2606:4700:4700::1001]/dns-query", true, false},
		},
		"dns.opendns.com": {
			{"[2620:119:35::35]:853", true, false},
			{"[2620:119:53::53]:853", true, false},
		},
		"dns10.quad9.net": {
			{"[2620:fe::10]:853", true, false},
			{"[2620:fe::fe:10]:853", true, false},
		},
	},
	b: map[string][]string{},
}

var IPv4Servers = DNSList{
	hostseq: []string{
		"dot.sb", "dns.google", "cloudflare-dns.com", "dns.opendns.com", "dns10.quad9.net",
	},
	m: map[string][]*dnsstat{
		"dot.sb": {
			{"185.222.222.222:853", true, false},
			{"45.11.45.11:853", true, false},
			{"https://doh.sb/dns-query", true, false},
		},
		"dns.google": {
			{"8.8.8.8:853", true, false},
			{"8.8.4.4:853", true, false},
			{"https://dns.google/resolve", true, false},
			{"https://8.8.8.8/resolve", true, false},
			{"https://8.8.4.4/resolve", true, false},
		},
		"cloudflare-dns.com": {
			{"1.1.1.1:853", true, false},
			{"1.0.0.1:853", true, false},
			{"https://cloudflare-dns.com/dns-query", true, false},
			{"https://1.1.1.1/dns-query", true, false},
			{"https://1.0.0.1/dns-query", true, false},
		},
		"dns.opendns.com": {
			{"208.67.222.222:853", true, false},
			{"208.67.220.220:853", true, false},
		},
		"dns10.quad9.net": {
			{"9.9.9.10:853", true, false},
			{"149.112.112.10:853", true, false},
		},
	},
	b: map[string][]string{},
}

var DefaultResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, nw, _ string) (net.Conn, error) {
		if ip.IsIPv6Available {
			return IPv6Servers.DialContext(ctx, nil, terasu.DefaultFirstFragmentLen)
		}
		return IPv4Servers.DialContext(ctx, nil, terasu.DefaultFirstFragmentLen)
	},
}
