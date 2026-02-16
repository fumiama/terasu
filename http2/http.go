// Package http2 is the same as the standard http lib with HTTP2 client support
package http2

import (
	"io"
	"net/http"
	"net/url"

	"github.com/fumiama/terasu/dns"
	"golang.org/x/net/http2"
)

// DefaultClient is the default HTTP2 client that supports HTTP/2 and DNS resolution
var DefaultClient = http.Client{
	Transport: &http2.Transport{
		DialTLSContext: dns.DialTLSContextWithConfig,
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
