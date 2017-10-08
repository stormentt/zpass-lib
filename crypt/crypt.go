package crypt

var (
	ConfigHasher  string
	ConfigCrypter string
)

func NewHasher(private, public []byte) Hasher {
	switch ConfigHasher {
	case "sha512":
		var hasher Sha512Hasher
		hasher.Key = private
		return &hasher
	}
	return nil
}

func NewCrypter(private, public []byte) Crypter {
	switch ConfigCrypter {
	case "chacha20poly1305":
		var crypter ChaCha20Crypter
		crypter.Key = private
		return &crypter
	}
	return nil
}
