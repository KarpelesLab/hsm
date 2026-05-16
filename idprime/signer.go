package idprime

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
)

// Config configures a Signer.
type Config struct {
	// Reader is a substring of the desired PC/SC reader name. Empty
	// matches the first available reader.
	Reader string

	// AID is the applet AID to SELECT. Defaults to DefaultAID
	// (IDPrime crypto applet).
	AID []byte

	// PIN is the token user PIN.
	PIN string

	// PINRef is the VERIFY-PIN P2 byte (default DefaultPINRefP2).
	PINRef byte

	// KeyRef is the on-card private-key reference (default DefaultKeyRef).
	KeyRef byte

	// AlgoRef is the algorithm reference passed to MSE:SET DST
	// (default DefaultAlgoRef — ECDSA-with-hash).
	AlgoRef byte

	// Public is the matching public key. It is returned from Public()
	// and used to dimension the raw r||s output.
	Public *ecdsa.PublicKey
}

// Signer implements crypto.Signer backed by the IDPrime applet on a
// PC/SC-attached token. Each Sign call performs a complete reader
// session (connect → select → verify PIN → MSE → PSO → disconnect),
// serialized by an internal mutex; the token PIN remains in memory for
// the lifetime of the Signer.
type Signer struct {
	cfg Config
	mu  sync.Mutex
}

// New returns a Signer ready to sign. It does not contact the token.
func New(cfg Config) (*Signer, error) {
	if cfg.PIN == "" {
		return nil, errors.New("idprime: PIN is required")
	}
	if cfg.Public == nil {
		return nil, errors.New("idprime: public key is required")
	}
	if cfg.AID == nil {
		cfg.AID = DefaultAID
	}
	if cfg.PINRef == 0 {
		cfg.PINRef = DefaultPINRefP2
	}
	if cfg.KeyRef == 0 {
		cfg.KeyRef = DefaultKeyRef
	}
	if cfg.AlgoRef == 0 {
		cfg.AlgoRef = DefaultAlgoRef
	}
	return &Signer{cfg: cfg}, nil
}

// Public returns the configured public key.
func (s *Signer) Public() crypto.PublicKey {
	return s.cfg.Public
}

// Sign produces an ECDSA signature over digest. The result is ASN.1 DER
// SEQUENCE { INTEGER r, INTEGER s } (the standard Go ecdsa encoding).
//
// digest length must match the curve / hash agreed with the applet via
// AlgoRef. For the default 0x54 + P-384 + SHA-384, digest must be 48
// bytes.
func (s *Signer) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, err := Connect()
	if err != nil {
		return nil, err
	}
	defer ctx.Close()

	readerName, err := ctx.FindReader(s.cfg.Reader)
	if err != nil {
		return nil, err
	}
	card, err := ctx.Connect(readerName, ShareShared, ProtoAny)
	if err != nil {
		return nil, err
	}
	defer card.Disconnect(LeaveCard)

	if err := card.BeginTransaction(); err != nil {
		return nil, err
	}
	defer card.EndTransaction(LeaveCard)

	if err := card.SelectApplet(s.cfg.AID); err != nil {
		return nil, err
	}
	if err := card.VerifyPIN(s.cfg.PIN, s.cfg.PINRef); err != nil {
		return nil, err
	}
	if err := card.MSESetDST(s.cfg.AlgoRef, s.cfg.KeyRef); err != nil {
		return nil, err
	}
	raw, err := card.PSOSign(digest)
	if err != nil {
		return nil, err
	}
	defer card.Logout()

	// Card returns r||s, both fixed to the curve byte size.
	curveSize := (s.cfg.Public.Curve.Params().BitSize + 7) / 8
	if len(raw) != 2*curveSize {
		return nil, fmt.Errorf("idprime: bad signature length %d (expected %d for curve %s)",
			len(raw), 2*curveSize, s.cfg.Public.Curve.Params().Name)
	}
	r := new(big.Int).SetBytes(raw[:curveSize])
	sInt := new(big.Int).SetBytes(raw[curveSize:])
	return asn1.Marshal(struct{ R, S *big.Int }{r, sInt})
}
