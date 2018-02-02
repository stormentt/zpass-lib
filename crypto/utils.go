package crypto

import (
	"hash"
	"io"
	"os"

	"github.com/pkg/errors"
)

const (
	ChunkSize = 128 * 1024
)

func HashFile(path string, hasher hash.Hash) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	data := make([]byte, ChunkSize)
	for {
		n, err := file.Read(data[:cap(data)])
		if err != nil {
			_ = file.Close()

			if err == io.EOF {
				break
			}
			return nil, errors.Wrap(err, "AuthPair: error signing file")
		}
		data = data[:n]
		_, _ = hasher.Write(data)
	}

	result := hasher.Sum(nil)
	return result, nil
}
