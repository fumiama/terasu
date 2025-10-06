package http2

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/http2"

	"github.com/fumiama/terasu"
	"github.com/fumiama/terasu/dns"
)

var (
	ErrEmptyHostAddress = errors.New("empty host addr")
)

var defaultDialer = net.Dialer{
	Timeout: 10 * time.Second,
}

func SetDefaultClientTimeout(t time.Duration) {
	defaultDialer.Timeout = t
}

var DefaultClient = http.Client{
	Transport: &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
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
				tlsConn = tls.Client(conn, cfg)
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
				tlsConn = tls.Client(conn, cfg)
				err = tlsConn.HandshakeContext(ctx)
				if err == nil {
					break
				}
				_ = tlsConn.Close()
				tlsConn = nil
			}
			return tlsConn, err
		},
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
