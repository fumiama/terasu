package dialer

import (
	"net"
	"syscall"
	"time"
)

// DefaultDialer is the default dialer used for establishing TCP connections
var DefaultDialer = net.Dialer{
	Timeout: 4 * time.Second,
}

// SetDefaultTimeout sets the default timeout for all HTTP2 client connections
func SetDefaultTimeout(t time.Duration) {
	DefaultDialer.Timeout = t
}

// SetDefaultControl sets control of the default dailer
func SetDefaultControl(c func(network string, address string, c syscall.RawConn) error) {
	DefaultDialer.Control = c
}
