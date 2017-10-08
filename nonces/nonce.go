package nonces

import (
	"time"
	"zpass-lib/crypt"
)

type Nonce struct {
	Value string
	Time  int64 `json:"nonce-time"`
}

func Make() Nonce {
	var n Nonce
	n.Value = crypt.RandStr(32)
	n.Time = time.Now().Unix()

	return n
}
