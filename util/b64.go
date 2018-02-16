package util

import (
	"encoding/base64"
)

//EncodeB64 encodes the given bytes into a base64 string
func EncodeB64(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}

//DecodeB64 decodes a base64 string into bytes
func DecodeB64(message string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(message)
}
