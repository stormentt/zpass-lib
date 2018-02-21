// Package nonces provides functions for generating unique nonces for use in APIs
package nonces

import (
	"time"

	"github.com/stormentt/zpass-lib/random"
)

//Nonce is a Value & Time pair for use as a guard against replay attacks
//
//Value should be randomly generated, and time should be the unix timestamp for when the nonce was made.
type Nonce struct {
	Value string `json:"value"`
	Time  int64  `json:"time"`
}

//New returns a new Nonce timestamped with the current time and a random 32 character alphanumeric string
func New() Nonce {
	return Nonce{
		Value: random.AlphaNum(32),
		Time:  time.Now().Unix(),
	}
}
