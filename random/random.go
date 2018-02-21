//Package random provides functions for generating cryptographically secure random values
package random

import (
	"crypto/rand"
	"math/big"

	"github.com/stormentt/zpass-lib/util"
)

// init checks if the system CSPRNG can generate values
//
// init will panic if it cannot read from the system CSPRNG
func init() {
	b := make([]byte, 256)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
}

// Bytes returns a random byte slice of length n
func Bytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return b
}

//BytesB64 returns a base64 encoded string containing n random bytes
func BytesB64(n int) string {
	str := util.EncodeB64(Bytes(n))
	return str
}

// Int returns a random integer between [0, max)
func Int(max int) int {
	bigMax := big.NewInt(int64(max))
	randInt, err := rand.Int(rand.Reader, bigMax)
	if err != nil {
		panic(err)
	}
	return int(randInt.Int64())
}

// AlphaNum returns a mixed-case alphanumeric string of the specified length
func AlphaNum(length int) string {
	alphanumeric := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	alphaLen := len(alphanumeric)

	ret := make([]byte, length)
	for i := 0; i < length; i++ {
		letter := Int(alphaLen)
		ret[i] = alphanumeric[letter]
	}

	return string(ret)
}
