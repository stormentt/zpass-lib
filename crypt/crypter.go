package crypt

//Crypter is an interface for encrypting & decrypting data, as well as deriving keys
type Crypter interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	GenKey() (err error)
	DeriveKey(password []byte) ([]byte, error)
	CalcKey(password, salt []byte) (err error)
}
