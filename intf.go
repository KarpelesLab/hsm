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
	// random bytes sourced from the HSM's RNG. Software backends draw
	// from crypto/rand; hardware backends talk to the device.
	//
	// The returned Reader matches crypto/rand.Read's contract: every
	// Read completely fills the supplied buffer. If the underlying
	// source fails for any reason — including a short read — the Read
	// PANICS instead of returning. Crypto callers must never silently
	// consume partial randomness, so the failure is made
	// non-recoverable on purpose.
	RandomSource() io.Reader
}

// mustFillReader wraps an io.Reader and panics if a Read cannot fill
// its buffer in full. Returned from every backend's RandomSource so the
// crypto/rand-style "always fills, otherwise crashes" guarantee is
// uniform regardless of which HSM is in use.
type mustFillReader struct{ src io.Reader }

func (r mustFillReader) Read(p []byte) (int, error) {
	n, err := io.ReadFull(r.src, p)
	if err != nil {
		panic("hsm: random source failed: " + err.Error())
	}
	return n, nil
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
