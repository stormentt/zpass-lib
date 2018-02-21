package zcrypto

import "fmt"

// IntKeyBadSizeError is returned if an invalid sized byte slice is used as an IntegrityKey.
type IntKeyBadSizeError struct {
	size int
}

func (e IntKeyBadSizeError) Error() string {
	return fmt.Sprintf("Integrity keys must be %d bytes, provided key was %d bytes.", IntKeySize, e.size)
}

// EncKeyBadSizeError is returned if an invalid sized byte slice is used as an EncryptionKey.
type EncKeyBadSizeError struct {
	size int
}

func (e EncKeyBadSizeError) Error() string {
	return fmt.Sprintf("Encryption keys must be %d bytes, provided key was %d bytes.", EncKeySize, e.size)
}

// CryptoProviderBadSizeError is returned if an invalid sized byte slice is used as an CryptoProvider.
type CryptoProviderBadSizeError struct {
	size int
}

func (e CryptoProviderBadSizeError) Error() string {
	return fmt.Sprintf("CryptoProvider keys must be %d bytes, provided key was %d bytes.", EncKeySize+IntKeySize+AuthFullSize, e.size)
}

//EncNonceBadSizeError is returned if an invalid sized byte slice is used as a SalsaNonce.
type EncNonceBadSizeError struct {
	size int
}

func (e EncNonceBadSizeError) Error() string {
	return fmt.Sprintf("Encryption nonces must be %d bytes, provided nonce was %d bytes.", EncNonceSize, e.size)
}

// AuthPairBadSizeError is returned if an invalid sized byte slice is used as an AuthPair.
type AuthPairBadSizeError struct {
	size int
}

func (e AuthPairBadSizeError) Error() string {
	return fmt.Sprintf("Authentication pairs must be either %d or %d bytes, provided pair was %d bytes.", AuthFullSize, AuthHalfSize, e.size)
}

// NoPrivKeyError is returned if an AuthPair attempts to do something that requires a private key (such as signing) and it does not have one.
type NoPrivKeyError struct{}

func (e NoPrivKeyError) Error() string {
	return "No private key"
}

// MsgTooShortError is returned if the ciphertext is too short to be valid.
type MsgTooShortError struct {
	wanted int
	size   int
}

func (e MsgTooShortError) Error() string {
	return fmt.Sprintf("Message too short, must be at least %d bytes, was %d bytes.", e.wanted, e.size)
}

// MACMismatchError is returned if the calculated MAC of a ciphertext does not match the provided MAC.
type MACMismatchError struct {
	testMAC []byte
	calcMAC []byte
}

func (e MACMismatchError) Error() string {
	return fmt.Sprintf("MAC Mismatch: provided MAC %x, calculated MAC %x", e.testMAC, e.calcMAC)
}

// UnintegrousReadError is returned if a read or seek is attempted on a tampered SalsaReader.
type UnintegrousReadError struct{}

func (e UnintegrousReadError) Error() string {
	return "Attempted read from unintegrous source"
}

// SoughtBehindError is returned if a seek is attempted behind the start of a SalsaReader's actual data.
type SoughtBehindError struct{}

func (e SoughtBehindError) Error() string {
	return "Attempted to seek before start of file"
}

// SalsaWriterClosedError is returned if a write is attempted to a closed salsa writer
type SalsaWriterClosedError struct{}

func (e SalsaWriterClosedError) Error() string {
	return "Attempted to write to a closed salsa writer"
}

// InvalidSignatureError is returned if a decryption is attempted on a tampered message
type InvalidSignatureError struct {
	sig []byte
}

func (e InvalidSignatureError) Error() string {
	return fmt.Sprintf("Invalid signature provided: %x", e.sig)
}
