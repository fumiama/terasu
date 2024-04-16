package terasu

import (
	"crypto/tls"
	"unsafe"
)

// Use terasu in this TLS conn
func Use(conn *tls.Conn) *tls.Conn {
	(*_trsconn)(unsafe.Pointer(conn)).handshakeFn = (*trsconn)(conn).clientHandshake
	return conn
}
