package dns

import (
	"context"
	"crypto/tls"
	"net"

	mtls "github.com/fumiama/terasu/tls"
)

// DialTLSContext fills http.Transport method with terasu and DNS
func DialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return DialTLSContextWithConfig(ctx, network, addr, nil)
}

// DialTLSContextWithConfig fills http2.Transport method with terasu and DNS
func DialTLSContextWithConfig(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
	return mtls.DialTLSContextCL(ctx, network, addr, cfg, nil)
}
