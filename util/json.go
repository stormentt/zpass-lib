package util

import (
	"bytes"
	"encoding/json"
	"strings"
)

func EncodeJson(object interface{}) (string, error) {
	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(object)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func DecodeJson(message string, object interface{}) error {
	decoder := json.NewDecoder(strings.NewReader(message))
	err := decoder.Decode(object)
	return err
}
