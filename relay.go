package terasu

import (
	"io"
	"sync"
)

type relay struct {
	mu  sync.Mutex
	buf chan []byte
	rem []byte
}

func newrelay() relay {
	return relay{buf: make(chan []byte, 64)}
}

// Read ...
func (r *relay) Read(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case len(p) == 0:
		return
	case len(p) <= len(r.rem):
		n = copy(p, r.rem)
		r.rem = r.rem[n:]
		if len(r.rem) == 0 {
			r.rem = nil
		}
		return
	case len(r.rem) > 0:
		n = copy(p, r.rem)
		r.rem = nil
		fallthrough
	default:
		for n < len(p) {
			buf := <-r.buf
			if len(buf) == 0 {
				err = io.EOF
				return
			}
			switch {
			case len(buf) >= len(p)-n:
				cnt := copy(p[n:], buf)
				n += cnt
				r.rem = buf[cnt:]
				if len(r.rem) == 0 {
					r.rem = nil
				}
				return
			default:
				n += copy(p[n:], buf)
			}
		}
	}
	panic("unexpected")
}

// Write ...
func (r *relay) Write(p []byte) (n int, err error) {
	buf := make([]byte, len(p))
	n = copy(buf, p)
	r.buf <- p
	return
}

// Close ...
func (r *relay) Close() error {
	close(r.buf)
	return nil
}
