package crypt

type SymmetricHasher struct {
	Key []byte
}

type Hasher interface {
	Digest(message []byte) []byte
	Verify(message, testMAC []byte) bool
}
