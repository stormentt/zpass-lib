package nonces

import (
	"time"
	"zpass-lib/random"
)

//Nonce is a Value & Time pair for use as a guard against replay attacks
//Value should be randomly generated, and time should be the unix timestamp for when the nonce was made.
type Nonce struct {
	Value string `json:"value"`
	Time  int64  `json:"time"`
}

//Make returns a new Nonce timestamped with the current time and a random 32 character alphanumeric string
func Make() (Nonce, error) {
	var n Nonce
	var err error
	n.Value, err = random.AlphaNum(32)
	n.Time = time.Now().Unix()

	return n, err
}
