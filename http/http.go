package http

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/fumiama/terasu"
	"github.com/fumiama/terasu/dns"
)

var (
	ErrNoTLSConnection  = errors.New("no tls connection")
	ErrEmptyHostAddress = errors.New("empty host addr")
)

var defaultDialer = net.Dialer{
	Timeout: 10 * time.Second,
}

func SetDefaultClientTimeout(t time.Duration) {
	defaultDialer.Timeout = t
}

var DefaultClient = http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			addrs, err := dns.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(addr) == 0 {
				return nil, ErrEmptyHostAddress
			}
			var conn net.Conn
			var tlsConn *tls.Conn
			for _, a := range addrs {
				if defaultDialer.Timeout != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(context.Background(), defaultDialer.Timeout)
					defer cancel()
				} else if !defaultDialer.Deadline.IsZero() {
					var cancel context.CancelFunc
					ctx, cancel = context.WithDeadline(context.Background(), defaultDialer.Deadline)
					defer cancel()
				}
				conn, err = defaultDialer.DialContext(ctx, network, net.JoinHostPort(a, port))
				if err != nil {
					continue
				}
				tlsConn = tls.Client(conn, &tls.Config{
					ServerName: host,
					MinVersion: tls.VersionTLS12,
				})
				// re-init ctx due to deadline settings in tcp dial
				if defaultDialer.Timeout != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(context.Background(), defaultDialer.Timeout)
					defer cancel()
				} else if !defaultDialer.Deadline.IsZero() {
					var cancel context.CancelFunc
					ctx, cancel = context.WithDeadline(context.Background(), defaultDialer.Deadline)
					defer cancel()
				}
				if terasu.DefaultFirstFragmentLen > 0 {
					err = terasu.Use(tlsConn).HandshakeContext(ctx, terasu.DefaultFirstFragmentLen)
				} else {
					err = tlsConn.HandshakeContext(ctx)
				}
				if err == nil {
					break
				}
				_ = tlsConn.Close()
				tlsConn = nil
				conn, err = defaultDialer.DialContext(ctx, network, net.JoinHostPort(a, port))
				if err != nil {
					continue
				}
				tlsConn = tls.Client(conn, &tls.Config{
					ServerName: host,
					MinVersion: tls.VersionTLS12,
				})
				err = tlsConn.HandshakeContext(ctx)
				if err == nil {
					break
				}
				_ = tlsConn.Close()
				tlsConn = nil
			}
			return tlsConn, err
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

func Get(url string) (resp *http.Response, err error) {
	return DefaultClient.Get(url)
}

func Head(url string) (resp *http.Response, err error) {
	return DefaultClient.Head(url)
}

func Post(url string, contentType string, body io.Reader) (resp *http.Response, err error) {
	return DefaultClient.Post(url, contentType, body)
}

func PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return DefaultClient.PostForm(url, data)
}
