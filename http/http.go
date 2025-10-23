// Package http is a wrapper around the standard http library with enhanced DNS resolution and TLS handling capabilities.
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
	// ErrNoTLSConnection is returned when a TLS connection cannot be established.
	ErrNoTLSConnection = errors.New("no tls connection")
	// ErrEmptyHostAddress is returned when the host address is empty.
	ErrEmptyHostAddress = errors.New("empty host addr")
)

// defaultDialer is the default dialer used for connecting to hosts.
var defaultDialer = net.Dialer{
	Timeout: 10 * time.Second,
}

// SetDefaultClientTimeout sets the default timeout for the client's dialer.
func SetDefaultClientTimeout(t time.Duration) {
	defaultDialer.Timeout = t
}

// DefaultClient is the default HTTP client with custom transport settings, including DNS resolution and TLS handling.
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
			if len(addrs) == 0 {
				return nil, ErrEmptyHostAddress
			}
			var conn net.Conn
			var tlsConn *tls.Conn
			for _, a := range addrs {
				// Apply timeout if set, otherwise use deadline
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
				tlsConn = tls.Client(terasu.NewConn(conn), &tls.Config{
					ServerName: host,
					MinVersion: tls.VersionTLS12,
				})
				// Re-initialize context due to potential deadline changes from TCP dial
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
				tlsConn = tls.Client(terasu.NewConn(conn), &tls.Config{
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

// Get performs an HTTP GET request using the default client.
func Get(url string) (resp *http.Response, err error) {
	return DefaultClient.Get(url)
}

// Head performs an HTTP HEAD request using the default client.
func Head(url string) (resp *http.Response, err error) {
	return DefaultClient.Head(url)
}

// Post performs an HTTP POST request using the default client.
func Post(url string, contentType string, body io.Reader) (resp *http.Response, err error) {
	return DefaultClient.Post(url, contentType, body)
}

// PostForm performs an HTTP POST request with form data using the default client.
func PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return DefaultClient.PostForm(url, data)
}
