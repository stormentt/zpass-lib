package streams

import "io"

type FullWriter interface {
	io.Writer
	io.Seeker
	io.Closer
}
