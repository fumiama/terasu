// Package http3 is the same as the standard http lib with HTTP3 client support
package http3

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	base14 "github.com/fumiama/go-base16384"
	"github.com/fumiama/terasu/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
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
	Transport: &http3.Transport{
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
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
			var qConn quic.EarlyConnection
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
				conn, err = net.ListenUDP("udp", nil)
				if err != nil {
					continue
				}
				ucon := conn.(*net.UDPConn)
				raddr := net.UDPAddrFromAddrPort(
					netip.MustParseAddrPort(net.JoinHostPort(a, port)),
				)
				n := (mrand.Intn(128) + 128) / 7 * 14
				w := bytes.NewBuffer(make([]byte, 0, base14.EncodeLen(n)))
				e := base14.NewEncoder(w)
				_, _ = io.CopyN(e, rand.Reader, int64(n))
				_ = e.Close()
				_, _ = ucon.WriteToUDP(w.Bytes(), raddr)
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
				qConn, err = quic.DialEarly(ctx, ucon, raddr, tlsCfg, cfg)
				if err == nil {
					break
				}
				panic(err)
			}
			return qConn, err
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
