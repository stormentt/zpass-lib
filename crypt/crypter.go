package crypt

type SymmetricCrypter struct {
	Key []byte
}

type AsymmetricCrypter struct {
	PublicKey  []byte
	PrivateKey []byte
}

type Crypter interface {
	Encrypt(plain []byte) ([]byte, []byte, error)
	Decrypt(ciphertext, nonce []byte) ([]byte, error)
	GenKey() []byte
	DeriveKey(password string) ([]byte, []byte, error)
	CalcKey(password string, salt []byte) ([]byte, error)
	SetKeys(private, public []byte)
}
