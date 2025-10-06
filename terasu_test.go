package terasu

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
)

func TestHTTPDialTLS13(t *testing.T) {
	cli := http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				conn, err := net.Dial("tcp", "18.65.159.2:443")
				if err != nil {
					return nil, err
				}
				t.Log("net.Dial succeeded")
				tlsConn := tls.Client(conn, &tls.Config{
					ServerName:         "huggingface.co",
					MinVersion:         tls.VersionTLS12,
					InsecureSkipVerify: true,
				})
				err = Use(tlsConn).Handshake(4)
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
				conn, err := net.Dial("tcp", "18.65.159.2:443")
				if err != nil {
					return nil, err
				}
				t.Log("net.Dial succeeded")
				tlsConn := tls.Client(conn, &tls.Config{
					ServerName:         "huggingface.co",
					InsecureSkipVerify: true,
					MinVersion:         tls.VersionTLS12,
					MaxVersion:         tls.VersionTLS12,
				})
				err = Use(tlsConn).Handshake(4)
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
