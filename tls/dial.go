package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"github.com/fumiama/terasu"
	"github.com/fumiama/terasu/dialer"
)

// ErrEmptyHostAddress is returned when DNS lookup for a host returns no addresses
var ErrEmptyHostAddress = errors.New("empty host addr")

// DialTLSContextWithConfigAndSystemResolver fills http2.Transport method with terasu and system DNS
func DialTLSContextWithConfigAndSystemResolver(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
	return DialTLSContextCL(ctx, network, addr, cfg, nil)
}

// DialTLSContextCL fills http2.Transport method with terasu
func DialTLSContextCL(
	ctx context.Context, network, addr string,
	cfg *tls.Config, lookup func(ctx context.Context, host string,
	) (addrs []string, err error)) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	var addrs []string
	if lookup != nil {
		addrs, err = lookup(ctx, host)
	} else {
		addrs, err = net.DefaultResolver.LookupHost(ctx, host)
	}
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, ErrEmptyHostAddress
	}
	if cfg == nil {
		cfg = &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		}
	}
	var conn net.Conn
	var tlsConn *tls.Conn
	for _, a := range addrs {
		if dialer.DefaultDialer.Timeout != 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.Background(), dialer.DefaultDialer.Timeout)
			defer cancel()
		} else if !dialer.DefaultDialer.Deadline.IsZero() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(context.Background(), dialer.DefaultDialer.Deadline)
			defer cancel()
		}
		conn, err = dialer.DefaultDialer.DialContext(ctx, network, net.JoinHostPort(a, port))
		if err != nil {
			continue
		}
		tlsConn = tls.Client(terasu.NewConn(conn), cfg)
		// re-init ctx due to deadline settings in tcp dial
		if dialer.DefaultDialer.Timeout != 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.Background(), dialer.DefaultDialer.Timeout)
			defer cancel()
		} else if !dialer.DefaultDialer.Deadline.IsZero() {
			var cancel context.CancelFunc
			ctx, cancel = context.WithDeadline(context.Background(), dialer.DefaultDialer.Deadline)
			defer cancel()
		}
		err = tlsConn.HandshakeContext(ctx)
		if err == nil {
			break
		}
		_ = tlsConn.Close()
		tlsConn = nil
		conn, err = dialer.DefaultDialer.DialContext(ctx, network, net.JoinHostPort(a, port))
		if err != nil {
			continue
		}
		tlsConn = tls.Client(terasu.NewConn(conn), cfg)
		err = tlsConn.HandshakeContext(ctx)
		if err == nil {
			break
		}
		_ = tlsConn.Close()
		tlsConn = nil
	}
	return tlsConn, err
}
