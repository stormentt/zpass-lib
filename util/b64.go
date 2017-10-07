package util

import "encoding/base64"

func EncodeB64(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}

func DecodeB64(message string) ([]byte, error) {
	bytes, err := base64.StdEncoding.DecodeString(message)
	return bytes, err
}
