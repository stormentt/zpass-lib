package zcrypto

import (
	"hash"
	"io"
	"os"

	"github.com/pkg/errors"
)

// HashFile uses the hasher to calculate a hash for a file
func HashFile(path string, hasher hash.Hash) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	data := make([]byte, FileChunkSize)
	for {
		n, err := file.Read(data[:cap(data)])
		if err != nil {
			_ = file.Close()

			if err == io.EOF {
				break
			}
			return nil, errors.WithStack(err)
		}
		data = data[:n]
		_, _ = hasher.Write(data)
	}

	result := hasher.Sum(nil)
	return result, nil
}

// HashReader uses the hasher to calculate a hash for a reader
func HashReader(r io.Reader, hasher hash.Hash) ([]byte, error) {
	data := make([]byte, FileChunkSize)
	for {
		n, err := r.Read(data[:cap(data)])
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		data = data[:n]
		hasher.Write(data)
	}

	return hasher.Sum(nil), nil
}
