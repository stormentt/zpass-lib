package crypto

import "fmt"

type IntKeyBadSizeError struct {
	size int
}

func (e IntKeyBadSizeError) Error() string {
	return fmt.Sprintf("Integrity keys must be %d bytes, provided key was %d bytes.", IntKeySize, e.size)
}

type EncKeyBadSizeError struct {
	size int
}

func (e EncKeyBadSizeError) Error() string {
	return fmt.Sprintf("Encryption keys must be %d bytes, provided key was %d bytes.", EncKeySize, e.size)
}

type CryptoProviderBadSizeError struct {
	size int
}

func (e CryptoProviderBadSizeError) Error() string {
	return fmt.Sprintf("CryptoProvider keys must be %d bytes, provided key was %d bytes.", EncKeySize+IntKeySize+AuthFullSize, e.size)
}

type EncNonceBadSizeError struct {
	size int
}

func (e EncNonceBadSizeError) Error() string {
	return fmt.Sprintf("Encryption nonces must be %d bytes, provided nonce was %d bytes.", EncNonceSize, e.size)
}

type AuthPairBadSizeError struct {
	size int
}

func (e AuthPairBadSizeError) Error() string {
	return fmt.Sprintf("Authentication pairs must be either %d or %d bytes, provided pair was %d bytes.", AuthFullSize, AuthHalfSize, e.size)
}

type NoPrivKeyError struct{}

func (e NoPrivKeyError) Error() string {
	return "No private key"
}

type MsgTooShortError struct {
	wanted int
	size   int
}

func (e MsgTooShortError) Error() string {
	return fmt.Sprintf("Message too short, must be at least %d bytes, was %d bytes.", e.wanted, e.size)
}

type MACMismatchError struct {
	testMAC []byte
	calcMAC []byte
}

func (e MACMismatchError) Error() string {
	return fmt.Sprintf("MAC Mismatch: provided MAC %x, calculated MAC %x", e.testMAC, e.calcMAC)
}

type UnintegrousReadError struct{}

func (e UnintegrousReadError) Error() string {
	return "Attempted read from unintegrous source"
}

type SoughtBehindError struct{}

func (e SoughtBehindError) Error() string {
	return "Attempted to seek before start of file"
}

type SalsaWriterClosedError struct{}

func (e SalsaWriterClosedError) Error() string {
	return "Attempted to write to a closed salsa writer"
}

type InvalidSignatureError struct {
	sig []byte
}

func (e InvalidSignatureError) Error() string {
	return fmt.Sprintf("Invalid signature provided: %x", e.sig)
}
