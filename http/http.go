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

	"github.com/FloatTech/ttl"

	"github.com/fumiama/terasu"
	"github.com/fumiama/terasu/dns"
)

var (
	ErrEmptyHostAddress = errors.New("empty host addr")
)

var DefaultDialer = net.Dialer{
	Timeout: time.Minute,
}

var lookupTable = ttl.NewCache[string, []string](time.Hour)

var DefaultClient = http.Client{
	Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if DefaultDialer.Timeout != 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, DefaultDialer.Timeout)
				defer cancel()
			}

			if !DefaultDialer.Deadline.IsZero() {
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, DefaultDialer.Deadline)
				defer cancel()
			}

			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			addrs := lookupTable.Get(host)
			if len(addrs) == 0 {
				addrs, err = dns.DefaultResolver.LookupHost(ctx, host)
				if err != nil {
					addrs, err = net.DefaultResolver.LookupHost(ctx, host)
					if err != nil {
						return nil, err
					}
				}
				lookupTable.Set(host, addrs)
			}
			if len(addr) == 0 {
				return nil, ErrEmptyHostAddress
			}
			var tlsConn *tls.Conn
			for _, a := range addrs {
				conn, err := DefaultDialer.DialContext(ctx, network, net.JoinHostPort(a, port))
				if err != nil {
					continue
				}
				tlsConn = tls.Client(conn, &tls.Config{
					ServerName: host,
				})
				err = terasu.Use(tlsConn).HandshakeContext(ctx, terasu.DefaultFirstFragmentLen)
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
