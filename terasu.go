package terasu

import (
	"context"
	"crypto/tls"
	"unsafe"
)

// Use terasu in this TLS conn
func Use(conn *tls.Conn) *Conn {
	return (*Conn)(conn)
}

// Handshake do terasu handshake in this TLS conn
func (conn *Conn) Handshake() error {
	expose := (*_trsconn)(unsafe.Pointer(conn))
	fnbak := expose.handshakeFn
	expose.handshakeFn = conn.clientHandshake
	defer func() { expose.handshakeFn = fnbak }()
	return (*tls.Conn)(conn).Handshake()
}

// Handshake do terasu handshake with ctx in this TLS conn
func (conn *Conn) HandshakeContext(ctx context.Context) error {
	expose := (*_trsconn)(unsafe.Pointer(conn))
	fnbak := expose.handshakeFn
	expose.handshakeFn = conn.clientHandshake
	defer func() { expose.handshakeFn = fnbak }()
	return (*tls.Conn)(conn).HandshakeContext(ctx)
}
