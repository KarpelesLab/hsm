package idprime

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"
)

// pkcs1v15Pad builds a PKCS#1 v1.5 padded block of length k around the
// supplied DigestInfo: 00 || 01 || PS (FF...FF) || 00 || di.
func pkcs1v15Pad(di []byte, k int) ([]byte, error) {
	if k < len(di)+11 {
		return nil, fmt.Errorf("idprime: RSA modulus too small for digest (%d < %d)", k, len(di)+11)
	}
	out := make([]byte, k)
	out[0] = 0x00
	out[1] = 0x01
	for i := 2; i < k-len(di)-1; i++ {
		out[i] = 0xFF
	}
	out[k-len(di)-1] = 0x00
	copy(out[k-len(di):], di)
	return out, nil
}

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

	// AlgoRef is the algorithm reference passed to MSE:SET DST. Defaults
	// to DefaultAlgoRef for ECDSA keys and DefaultRSAAlgoRef for RSA
	// keys. Callers can override either default explicitly.
	AlgoRef byte

	// Public is the matching public key (*ecdsa.PublicKey or
	// *rsa.PublicKey). It is returned from Public() and used to dispatch
	// the signing routine and dimension the raw output.
	Public crypto.PublicKey
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
	switch cfg.Public.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		// supported
	default:
		return nil, fmt.Errorf("idprime: unsupported public key type %T", cfg.Public)
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
		if _, isRSA := cfg.Public.(*rsa.PublicKey); isRSA {
			cfg.AlgoRef = DefaultRSAAlgoRef
		} else {
			cfg.AlgoRef = DefaultAlgoRef
		}
	}
	return &Signer{cfg: cfg}, nil
}

// Public returns the configured public key.
func (s *Signer) Public() crypto.PublicKey {
	return s.cfg.Public
}

// Sign produces a signature over digest. For ECDSA keys the result is
// ASN.1 DER SEQUENCE { INTEGER r, INTEGER s } (standard Go ecdsa
// encoding). For RSA keys the result is a PKCS#1 v1.5 signature; RSA-PSS
// is not supported by the IDPrime crypto applet path.
//
// digest must be the raw hash output for the hash named by opts (e.g.
// 32 bytes for crypto.SHA256). For the default ECDSA configuration the
// hash size must match the curve.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, errors.New("idprime: RSA-PSS is not supported")
	}

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
	defer card.Logout()

	switch pub := s.cfg.Public.(type) {
	case *ecdsa.PublicKey:
		return signECDSA(card, pub, digest)
	case *rsa.PublicKey:
		return signRSA(card, pub, digest, opts)
	default:
		return nil, fmt.Errorf("idprime: unsupported public key type %T", s.cfg.Public)
	}
}

func signECDSA(card *Card, pub *ecdsa.PublicKey, digest []byte) ([]byte, error) {
	raw, err := card.PSOSign(digest)
	if err != nil {
		return nil, err
	}
	curveSize := (pub.Curve.Params().BitSize + 7) / 8
	if len(raw) != 2*curveSize {
		return nil, fmt.Errorf("idprime: bad signature length %d (expected %d for curve %s)",
			len(raw), 2*curveSize, pub.Curve.Params().Name)
	}
	r := new(big.Int).SetBytes(raw[:curveSize])
	s := new(big.Int).SetBytes(raw[curveSize:])
	return asn1.Marshal(struct{ R, S *big.Int }{r, s})
}

func signRSA(card *Card, pub *rsa.PublicKey, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()
	prefix, ok := pkcs1v15HashPrefixes[hash]
	if !ok {
		return nil, fmt.Errorf("idprime: unsupported RSA hash %s", hash)
	}
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("idprime: digest length %d does not match hash %s (%d)",
			len(digest), hash, hash.Size())
	}
	di := make([]byte, 0, len(prefix)+len(digest))
	di = append(di, prefix...)
	di = append(di, digest...)
	// IDPrime's default RSA algoRef (0x02) expects a fully PKCS#1 v1.5
	// padded block of length == modulus byte size; the card performs the
	// modular exponentiation and nothing else.
	k := (pub.N.BitLen() + 7) / 8
	padded, err := pkcs1v15Pad(di, k)
	if err != nil {
		return nil, err
	}
	sig, err := card.PSOSignRSA(padded)
	if err != nil {
		return nil, err
	}
	if len(sig) != k {
		return nil, fmt.Errorf("idprime: RSA signature length %d (expected %d)", len(sig), k)
	}
	return sig, nil
}

// pkcs1v15HashPrefixes is the DigestInfo prefix for each supported hash,
// matching the table inside crypto/rsa for PKCS#1 v1.5 signatures.
var pkcs1v15HashPrefixes = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}
