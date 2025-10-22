package terasu

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
)

func TestHTTPDialTLS13(t *testing.T) {
	cli := http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				conn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(
					netip.MustParseAddrPort("52.222.136.117:443"),
				))
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
				conn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(
					netip.MustParseAddrPort("52.222.136.117:443"),
				))
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
