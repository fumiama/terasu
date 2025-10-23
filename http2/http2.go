// Package http2 is the same as the standard http lib with HTTP2 client support
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

// ErrEmptyHostAddress is returned when DNS lookup for a host returns no addresses
var ErrEmptyHostAddress = errors.New("empty host addr")

// defaultDialer is the default dialer used for establishing TCP connections
var defaultDialer = net.Dialer{
	Timeout: 10 * time.Second,
}

// SetDefaultClientTimeout sets the default timeout for all HTTP2 client connections
func SetDefaultClientTimeout(t time.Duration) {
	defaultDialer.Timeout = t
}

// DefaultClient is the default HTTP2 client that supports HTTP/2 and DNS resolution
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
			if len(addrs) == 0 {
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
				tlsConn = tls.Client(terasu.NewConn(conn), cfg)
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
				err = tlsConn.HandshakeContext(ctx)
				if err == nil {
					break
				}
				_ = tlsConn.Close()
				tlsConn = nil
				conn, err = defaultDialer.DialContext(ctx, network, net.JoinHostPort(a, port))
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
		},
	},
}

// Get sends an HTTP GET request to the specified URL using the default HTTP2 client
func Get(url string) (resp *http.Response, err error) {
	return DefaultClient.Get(url)
}

// Head sends an HTTP HEAD request to the specified URL using the default HTTP2 client
func Head(url string) (resp *http.Response, err error) {
	return DefaultClient.Head(url)
}

// Post sends an HTTP POST request to the specified URL with the given content type and body using the default HTTP2 client
func Post(url string, contentType string, body io.Reader) (resp *http.Response, err error) {
	return DefaultClient.Post(url, contentType, body)
}

// PostForm sends an HTTP POST request with form data to the specified URL using the default HTTP2 client
func PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return DefaultClient.PostForm(url, data)
}
