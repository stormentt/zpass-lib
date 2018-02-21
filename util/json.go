package util

import (
	"bytes"
	"encoding/json"
	"strings"
)

//EncodeJSON encodes an object into a json string
func EncodeJSON(object interface{}) (string, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(object)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

//DecodeJSON decodes a json string into the given interface
func DecodeJSON(message string, object interface{}) error {
	decoder := json.NewDecoder(strings.NewReader(message))
	err := decoder.Decode(object)
	return err
}
