package util

import (
	"encoding/base64"
	log "github.com/sirupsen/logrus"
)

//EncodeB64 encodes the given bytes into a base64 string
func EncodeB64(bytes []byte) string {
	return base64.StdEncoding.EncodeToString(bytes)
}

//DecodeB64 decodes a base64 string into bytes
func DecodeB64(message string) ([]byte, error) {
	bytes, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		log.WithFields(log.Fields{
			"String": message,
			"Error":  err,
		}).Debug("Unable to decode base64 string")
		return nil, err
	}
	return bytes, nil
}
