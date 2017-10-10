package nonces

import (
	"time"
	"zpass-lib/random"
)

type Nonce struct {
	Value string
	Time  int64
}

func Make() (Nonce, error) {
	var n Nonce
	var err error
	n.Value, err = random.AlphaNum(32)
	n.Time = time.Now().Unix()

	return n, err
}
