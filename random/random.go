//Package random provides functions for generating random values
package random

import (
	"crypto/rand"
	"math/big"
	"github.com/stormentt/zpass-lib/util"
)

// Bytes returns a random byte slice of length n
// If there's an error generating the bytes it'll return (nil, error)
func Bytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

//ByteB64 returns a base64 encoded string containing n random bytes
func BytesB64(n int) (string, error) {
	bytes, err := Bytes(n)
	if err != nil {
		return "", err
	}

	str := util.EncodeB64(bytes)
	return str, nil
}

// Int returns a random integer between [0, max)
func Int(max int64) (int64, error) {
	bigMax := big.NewInt(max)
	randInt, err := rand.Int(rand.Reader, bigMax)
	if err != nil {
		return 0, err
	}

	return randInt.Int64(), nil
}

// AlphaNum returns a mixed-case alphanumeric string of the specified length
func AlphaNum(length int) (string, error) {
	alphanumeric := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		letter, err := Int(int64(len(alphanumeric)))
		if err != nil {
			return "", err
		}

		ret[i] = alphanumeric[letter]
	}

	return string(ret), nil
}
