<div align="center">

# TeRaSu (TRS)

よの光遍く空へ照しつつ

土棲むものは孰れか見ゆや

![counter](https://counter.seku.su/cmoe?name=trs&theme=mb)

</div>

## Usage

```go
cli := http.Client{
    Transport: &http.Transport{
        DialTLS: func(network, addr string) (net.Conn, error) {
            host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
            addrs, err := net.DefaultResolver.LookupHost(ctx, host)
            if err != nil {
                return nil, err
            }
            conn, err := net.Dial(network, net.JoinHostPort(addrs[0], port))
            if err != nil {
                return nil, err
            }
            tlsConn := tls.Client(conn, &tls.Config{
                ServerName: host,
            })
            err = terasu.Use(tlsConn).Handshake()
            if err != nil {
                _ = tlsConn.Close()
                return nil, err
            }
            return tlsConn, nil
        },
    },
}
resp, err := cli.Get(url)
```
