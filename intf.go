package hsm

import "crypto"

type HSM interface {
	Ready() bool
	ListKeys() ([]Key, error)
}

type Key interface {
	crypto.Signer
	String() string
}
