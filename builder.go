package terasu

import (
	"io"
	"net"
)

type builder net.Buffers

func newbuilder() builder {
	return builder{}
}

// move is write without copy
func (bd *builder) move(b []byte) {
	*bd = append(*bd, b)
}

func (bd *builder) send(conn *net.TCPConn, rs ...io.Reader) (int64, error) {
	if len(rs) == 0 {
		return conn.ReadFrom((*net.Buffers)(bd))
	}
	return conn.ReadFrom(io.MultiReader(append([]io.Reader{(*net.Buffers)(bd)}, rs...)...))
}

func (bd *builder) reset() {
	*bd = (*bd)[:0]
}
