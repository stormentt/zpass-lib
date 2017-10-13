package crypt

type SymmetricCrypter struct {
	Key []byte
}

type AsymmetricCrypter struct {
	PublicKey  []byte
	PrivateKey []byte
}

//Crypter is an interface for encrypting & decrypting data, as well as deriving keys
type Crypter interface {
	//Encrypt encrypts the plaintext bytes with the Crypter's key and returns the ciphertext
	Encrypt(plain []byte) ([]byte, error)
	//Decrypt decrypts the plaintext bytes with the Crypter's key and returns the plaintext
	Decrypt(encrypted []byte) ([]byte, error)
	//GenKey generates a random byte slice suitable for use as an encryption key with the Crypter
	GenKey() ([]byte, error)
	//DeriveKey uses a KDF to turn a password into an encryption key. DeriveKey returns the encryption key & the salt used for key derivation
	DeriveKey(password string) ([]byte, []byte, error)
	//CalcKey uses a KDF to turn a password & salt into an encryption key.
	CalcKey(password string, salt []byte) ([]byte, error)
	//SetKeys sets the keys for the Crypter
	SetKeys(private, public []byte)
}
