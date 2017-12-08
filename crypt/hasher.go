package crypt

//Hasher is used to calculate & verify HMAC digests for messages
type Hasher interface {
	Digest(message []byte) []byte
	DigestFile(path string) ([]byte, error)
	Verify(message, testMAC []byte) bool
	VerifyFile(path string, testMAC []byte) bool
	GenKey() (key []byte, err error)
}
