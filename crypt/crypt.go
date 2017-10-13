package crypt

var (
	//ConfigHasher is which hasher to return when NewHasher() is called
	ConfigHasher string
	//ConfigCrypter is which crypter to return when NewCrypter() is called
	ConfigCrypter string
)

//NewHasher returns a Hasher with the specified private & public keys
//Right now only symmetric key Hashers are supported but eventually there will be support for asymmetric crypto
func NewHasher(private, public []byte) Hasher {
	switch ConfigHasher {
	case "sha512":
		var hasher Sha512Hasher
		hasher.Key = private
		return &hasher
	}
	return nil
}

//NewCrypter returns a Crypter with the specified private & public keys
//Right now only symmetric key Crypters are supported but eventually there will be support for asymmetric crypto
func NewCrypter(private, public []byte) Crypter {
	switch ConfigCrypter {
	case "chacha20poly1305":
		var crypter ChaCha20Crypter
		crypter.Key = private
		return &crypter
	}
	return nil
}
