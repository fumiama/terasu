package terasu

import (
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultFirstFragmentLen ...
var DefaultFirstFragmentLen = 4

// Conn remote: real server; local: relay
type Conn struct {
	relay relay
	isold uintptr
	init  *sync.Once
	conn  *net.TCPConn
}

// NewConn wraps *net.TCPConn (net.Conn must be *net.TCPConn)
func NewConn(conn net.Conn) *Conn {
	c := &Conn{
		relay: newrelay(),
		init:  &sync.Once{},
		conn:  conn.(*net.TCPConn),
	}
	switch o := conn.(type) {
	case *net.TCPConn:
		c.conn = o
	default:
		panic("unsupported conn type: " + reflect.TypeOf(conn).String())
	}
	return c
}

// Write is send
func (conn *Conn) Write(b []byte) (int, error) {
	if atomic.LoadUintptr(&conn.isold) != 0 || DefaultFirstFragmentLen == 0 {
		return conn.conn.Write(b)
	}
	go conn.init.Do(func() {
		_, err := io.Copy(conn, &conn.relay)
		if err != nil {
			_ = conn.relay.Close()
		}
	})
	return conn.relay.Write(b)
}

// ReadFrom when client want to send to server, detect and split.
func (conn *Conn) ReadFrom(r io.Reader) (n int64, err error) {
	if atomic.LoadUintptr(&conn.isold) != 0 || DefaultFirstFragmentLen == 0 {
		return conn.conn.ReadFrom(r)
	}

	defer atomic.StoreUintptr(&conn.isold, 1)

	// ContentType [0:1]
	// Version [1:3]
	// Length [3:5]
	// Payload[Length] ->
	//   HandshakeType [5:6]
	//   HandshakeBodyLength [6:9]
	var header [1 + 2 + 2 + 1 + 3]byte
	x := DefaultFirstFragmentLen
	// preserved as tmp vars
	plen := uint16(0)
	var b []byte
	bd := newbuilder()

	// ContentType [0:1] Version [1:2] 0x03
	_, err = io.ReadFull(r, header[:2])
	if err != nil {
		return
	}
	// recordTypeHandshake = 0x16
	// Version [1:2] = 0x03
	if binary.BigEndian.Uint16(header[:2]) != 0x1603 {
		bd.move(header[:2])
		goto PIPE
	}
	// Version [2:3] (0x01 1.0) (0x02 1.1) (0x03 1.2) (0x04 1.3)
	_, err = io.ReadFull(r, header[2:3])
	if err != nil {
		return
	}
	// skip unsupported version
	if header[2] < 1 || header[2] > 4 {
		bd.move(header[:3])
		goto PIPE
	}
	// Length [3:5] HandshakeType [5:6]
	_, err = io.ReadFull(r, header[3:6])
	if err != nil {
		return
	}
	// skip unsupported handshake type
	if header[5] != 0x01 { // client hello
		bd.move(header[:6])
		goto PIPE
	}
	// HandshakeBodyLength [6:9]
	_, err = io.ReadFull(r, header[6:9])
	if err != nil {
		return
	}
	plen = binary.BigEndian.Uint16(header[3:5])
	if binary.BigEndian.Uint32(header[5:9])&0x00ffffff+ // body
		// handshake type, body length
		1+3 !=
		// payload length
		uint32(plen) {
		bd.move(header[:9])
		goto PIPE
	}

	// split
	if x <= 4 { // first is in header range
		// first
		binary.BigEndian.PutUint16(header[3:5], uint16(x))
		bd.move(header[:5+x])
		n, err = bd.send(conn.conn)
		bd.reset()
		if err != nil {
			return
		}
		copy(header[5:9-x], header[5+x:9])
		// second
		binary.BigEndian.PutUint16(header[3:5], plen-uint16(x))
		bd.move(header[:9-x])
		goto PIPE
	}
	// first is out of header range
	// first
	binary.BigEndian.PutUint16(header[3:5], uint16(x))
	bd.move(header[:9])
	b = make([]byte, x-4)
	_, err = io.ReadFull(r, b)
	if err != nil {
		return
	}
	bd.move(b)
	n, err = bd.send(conn.conn)
	bd.reset()
	if err != nil {
		return
	}
	// second
	binary.BigEndian.PutUint16(header[3:5], plen-uint16(x))
	bd.move(header[:5])
PIPE:
	if err != nil {
		return
	}
	_ = conn.relay.Close()
	cnt, err := bd.send(conn.conn, r)
	n += cnt
	return
}

// Read is recv
func (conn *Conn) Read(b []byte) (int, error) {
	return conn.conn.Read(b)
}

// WriteTo remote response and releay it to local client without any change.
func (conn *Conn) WriteTo(w io.Writer) (int64, error) {
	return conn.conn.WriteTo(w)
}

// Close closes the connection.
func (conn *Conn) Close() error {
	return conn.conn.Close()
}

// LocalAddr returns the local network address.
func (conn *Conn) LocalAddr() net.Addr {
	return conn.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (conn *Conn) RemoteAddr() net.Addr {
	return conn.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
func (conn *Conn) SetDeadline(t time.Time) error {
	return conn.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for future Read calls.
func (conn *Conn) SetReadDeadline(t time.Time) error {
	return conn.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future Write calls.
func (conn *Conn) SetWriteDeadline(t time.Time) error {
	return conn.conn.SetWriteDeadline(t)
}
