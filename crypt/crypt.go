package crypt

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/stormentt/zpass-lib/crypt/ChaCha20Poly1305"
	"github.com/stormentt/zpass-lib/crypt/SHA512"
)

var (
	//ConfigHasher is which hasher to return when NewHasher() is called
	ConfigHasher string
	//ConfigCrypter is which crypter to return when NewCrypter() is called
	ConfigCrypter string
)

//NewHasher returns a Hasher with the specified private & public keys
//Right now only symmetric key Hashers are supported but eventually there will be support for asymmetric crypto
func NewHasher(private, public []byte) (Hasher, error) {
	switch ConfigHasher {
	case "sha512":
		return SHA512.Create(private)
	default:
		log.WithFields(log.Fields{
			"error":  "Invalid hasher",
			"hasher": ConfigHasher,
		}).Error("Invalid hasher requested")
		return nil, errors.New("Invalid hasher")
	}
}

//NewCrypter returns a Crypter with the specified private & public keys
//Right now only symmetric key Crypters are supported but eventually there will be support for asymmetric crypto
func NewCrypter(private, public []byte) (Crypter, error) {
	switch ConfigCrypter {
	case "chacha20poly1305":
		return ChaCha20Poly1305.Create(private)
	default:
		log.WithFields(log.Fields{
			"error":   "Invalid crypter",
			"crypter": ConfigCrypter,
		}).Error("Invalid crypter requested")
		return nil, errors.New("Invalid crypter")
	}
}
