package crypt

type SymmetricHasher struct {
	Key []byte
}

//Hasher is used to calculate & verify HMAC digests for messages
type Hasher interface {
	//Digest uses the Hasher's key to calculate a MAC
	Digest(message []byte) []byte
	//Verify digests the message & compares the resultant MAC to the testMAC, returning true if they match, false otherwise
	Verify(message, testMAC []byte) bool
	//GenKey generates a random byte slice suitable for use as a digest key for this Hasher
	GenKey() ([]byte, error)
}
