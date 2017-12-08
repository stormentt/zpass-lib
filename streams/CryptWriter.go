package streams

import "io"

type CryptWriter interface {
	io.WriteCloser
}
