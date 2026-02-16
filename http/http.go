// Package http is a wrapper around the standard http library with enhanced DNS resolution and TLS handling capabilities.
package http

import (
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/fumiama/terasu/dns"
)

// DefaultClient is the default HTTP client with custom transport settings, including DNS resolution and TLS handling.
var DefaultClient = http.Client{
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialTLSContext:        dns.DialTLSContext,
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
