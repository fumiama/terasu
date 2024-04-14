package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/fumiama/terasu"
)

func main() {
	u := flag.String("url", "https://huggingface.co/", "the url to get")
	ipport := flag.String("dest", "18.65.159.2:443", "host:port")
	flag.Parse()
	if !strings.HasPrefix(*u, "https://") {
		fmt.Println("ERROR: invalid url")
		return
	}
	host := (*u)[8:]
	host, _, _ = strings.Cut(host, "/")
	cli := http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) {
				conn, err := net.Dial("tcp", *ipport)
				if err != nil {
					return nil, err
				}
				return terasu.Use(tls.Client(conn, &tls.Config{
					ServerName:         host,
					InsecureSkipVerify: true,
				})), nil
			},
		},
	}
	resp, err := cli.Get(*u)
	if err != nil {
		fmt.Println("ERROR:", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println("ERROR:", "status code:", resp.StatusCode)
		return
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("ERROR:", err)
		return
	}
	fmt.Print(string(data))
}
