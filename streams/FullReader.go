package streams

import "io"

type FullReader interface {
	io.Reader
	io.Seeker
	io.Closer
}
