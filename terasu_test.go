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
				return Use(tls.Client(conn, &tls.Config{
					ServerName:         "huggingface.co",
					InsecureSkipVerify: true,
				})), nil
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
				return Use(tls.Client(conn, &tls.Config{
					ServerName:         "huggingface.co",
					InsecureSkipVerify: true,
					MaxVersion:         tls.VersionTLS12,
				})), nil
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
