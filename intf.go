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
	// Certificate returns the X.509 certificate associated with this key,
	// or nil if no certificate is associated or available.
	Certificate() *x509.Certificate
	String() string
}
