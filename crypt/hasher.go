package crypt

//Hasher is used to calculate & verify HMAC digests for messages
type Hasher interface {
	Digest(message []byte) []byte
	Verify(message, testMAC []byte) bool
	GenKey() (err error)
}
