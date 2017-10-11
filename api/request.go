package api

import (
	"zpass-lib/canister"
	"zpass-lib/crypt"
)

type Message struct {
	Data    Canister
	Valid   bool
	HMACB64 string
}

func NewMessage() *Message {
	var m NewMessage
	m.Data = canister.New()
	m.Valid = false
	return &m
}

func Parse(input string) (*Message, error) {
	var m NewMessage
	m.Data, err = canister.Fill(input)
	m.Valid = false
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Message) CalcHMAC(authKey []byte) []byte {
	//TODO: Write validation functions for this
}
