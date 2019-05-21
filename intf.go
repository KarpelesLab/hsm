package hsm

import (
	"crypto"
	"crypto/x509"
)

type HSM interface {
	Ready() bool
	ListKeys() ([]Key, error)
	ListKeysByName(name string) ([]Key, error)

	PutCertificate(name string, cert *x509.Certificate) error
	GetCertificate(name string) (*x509.Certificate, error)
}

type Key interface {
	crypto.Signer
	PublicBlob() ([]byte, error)
	String() string
}
