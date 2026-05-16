package hsm

import (
	"crypto"
	"crypto/x509"
	"io"
)

type HSM interface {
	Ready() bool
	ListKeys() ([]Key, error)
	ListKeysByName(name string) ([]Key, error)

	PutCertificate(name string, cert *x509.Certificate) error
	GetCertificate(name string) (*x509.Certificate, error)

	// RandomSource returns an io.Reader that yields cryptographically
	// random bytes sourced from the HSM's RNG. Software backends return
	// crypto/rand.Reader. Hardware backends return a Reader that talks
	// to the device; each Read may transparently issue multiple
	// underlying commands to fill the requested buffer.
	RandomSource() io.Reader
}

type Key interface {
	crypto.Signer
	PublicBlob() ([]byte, error)
	// Certificate returns the X.509 leaf certificate associated with
	// this key, or nil if no certificate is associated or available.
	Certificate() *x509.Certificate
	// CertificateChain returns the X.509 chain associated with this
	// key, starting with the leaf and followed by any known
	// intermediate / root certificates. Returns nil when no leaf is
	// available.
	CertificateChain() []*x509.Certificate
	String() string
}
