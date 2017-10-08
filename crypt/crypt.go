package crypt

import (
	"crypto/rand"
	"encoding/base64"
	"math/big"
)

var (
	ConfigHasher  string
	ConfigCrypter string
)

//RandBytes generates n random bytes
func RandBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

//RandBytesB64 generates n random bytes in Base64 encoding`
func RandBytesB64(n int) string {
	bytes := RandBytes(n)
	str := base64.StdEncoding.EncodeToString(bytes)
	return str
}

//RandStr returns a random alphanumeric string
func RandStr(length int) string {
	alphanumeric := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		letter, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphanumeric))))

		ret[i] = alphanumeric[letter.Int64()]
	}
	return string(ret)
}

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
