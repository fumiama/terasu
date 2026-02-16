package terasu

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/fumiama/terasu/dialer"
)

func TestHTTPDialDifferentFragLen(t *testing.T) {
	cli := http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				conn, err := dialer.DefaultDialer.Dial("tcp", "3.164.110.114:443")
				if err != nil {
					return nil, err
				}
				t.Log("net.Dial succeeded")
				tlsConn := tls.Client(NewConn(conn), &tls.Config{
					ServerName:         "huggingface.co",
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: true,
				})
				err = tlsConn.Handshake()
				if err != nil {
					_ = tlsConn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
	}
	for i := 0; i < 10; i++ {
		// will fail when i=0 in CN
		DefaultFirstFragmentLen = i
		resp, err := cli.Get("https://huggingface.co/")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatal("status code:", resp.StatusCode)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(string(data))
	}
}

func TestHTTPDialTLS13(t *testing.T) {
	cli := http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				conn, err := dialer.DefaultDialer.Dial("tcp", "3.164.110.114:443")
				if err != nil {
					return nil, err
				}
				t.Log("net.Dial succeeded")
				tlsConn := tls.Client(NewConn(conn), &tls.Config{
					ServerName:         "huggingface.co",
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: true,
				})
				err = tlsConn.Handshake()
				if err != nil {
					_ = tlsConn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
	}
	resp, err := cli.Get("https://huggingface.co/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("status code:", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}

func TestHTTPDialTLS12(t *testing.T) {
	cli := http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				conn, err := dialer.DefaultDialer.Dial("tcp", "3.164.110.114:443")
				if err != nil {
					return nil, err
				}
				t.Log("net.Dial succeeded")
				tlsConn := tls.Client(NewConn(conn), &tls.Config{
					ServerName:         "huggingface.co",
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
					MaxVersion:         tls.VersionTLS12,
				})
				err = tlsConn.Handshake()
				if err != nil {
					_ = tlsConn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
	}
	resp, err := cli.Get("https://huggingface.co/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("status code:", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(data))
}
