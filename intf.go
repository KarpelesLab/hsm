package hsm

import "crypto"

type HSM interface {
	Ready() bool
	ListKeys() ([]Key, error)
	ListKeysByName(name string) ([]Key, error)
}

type Key interface {
	crypto.Signer
	PublicBlob() ([]byte, error)
	String() string
}
