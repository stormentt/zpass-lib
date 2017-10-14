package util

import (
	"bytes"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"strings"
)

//EncodeJson encodes an object into a json string
func EncodeJson(object interface{}) (string, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(object)
	if err != nil {
		log.WithFields(log.Fields{
			"Object": object,
			"Error":  err,
		}).Debug("Unable to encode json object")
		return "", err
	}
	return buf.String(), nil
}

//DecodeJson decodes a json string into the given interface
func DecodeJson(message string, object interface{}) error {
	decoder := json.NewDecoder(strings.NewReader(message))
	err := decoder.Decode(object)
	if err != nil {
		log.WithFields(log.Fields{
			"String": message,
			"Error":  err,
		}).Debug("Unable to decode json string")
		return err
	}
	return nil
}
