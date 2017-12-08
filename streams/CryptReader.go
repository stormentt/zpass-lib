package streams

import "io"

type CryptReader interface {
	io.Reader
	Initialize() (err error)
}
