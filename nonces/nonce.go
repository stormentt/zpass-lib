package nonces

import (
	"time"
	"zpass-lib/crypt"
)

type Nonce struct {
	Nonce     string
	NonceTime int64 `json:"nonce-time"`
}

func Make() Nonce {
	var n Nonce
	n.Nonce = crypt.RandStr(32)
	n.NonceTime = time.Now().Unix()

	return n
}
