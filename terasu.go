package terasu

import (
	"crypto/tls"
	"unsafe"
)

// Use terasu in this TLS conn
func Use(conn *tls.Conn) *tls.Conn {
	trsConn := (*trsconn)(unsafe.Pointer(conn))
	trsConn.handshakeFn = trsConn.clientHandshake
	return (*tls.Conn)(unsafe.Pointer(trsConn))
}
