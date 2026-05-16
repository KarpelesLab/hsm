package hsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/KarpelesLab/hsm/idprime"
	"golang.org/x/term"
)

// IDPrime is an HSM backed by a Thales / Gemalto IDPrime crypto-applet
// smart card (e.g. SafeNet eToken 5110+ FIPS, IDPrime MD), accessed via
// pcscd over its local Unix socket. No CGO, no closed-source library.
//
// Configuration via environment variables read by NewIDPrime:
//
//	IDPRIME_PIN        token user PIN (prompted on tty if absent)
//	IDPRIME_READER     reader name substring (default: first reader)
//	IDPRIME_AID        applet AID, hex (default: IDPrime crypto applet)
//
//	IDPRIME_CERT       optional path to a PEM leaf certificate. When set,
//	                   only that cert is exposed (no on-card enumeration).
//	                   Otherwise: the card is walked, every kxc## file is
//	                   decompressed, expired certs are dropped, and each
//	                   remaining cert with a matching on-card private key
//	                   is exposed as a Key.
//	IDPRIME_KEY_REF    optional override (only honored with IDPRIME_CERT;
//	                   hex byte). Default: discovered from the card.
//	IDPRIME_ALGO_REF   optional override, hex byte. Default: 0x54
//	                   (ECDSA) / 0x02 (RSA).
//	IDPRIME_ALLOW_EXPIRED  if "1", include expired certificates during
//	                   enumeration (intended for testing only).
type IDPrime struct {
	reader        string
	pin           string
	aid           []byte
	keys          []*idprimeKey
	intermediates []*x509.Certificate // shared chain bundle from msroots, if any
}

// NewIDPrime constructs an IDPrime HSM from environment variables.
func NewIDPrime() (HSM, error) {
	h := &IDPrime{reader: os.Getenv("IDPRIME_READER")}
	if v := os.Getenv("IDPRIME_AID"); v != "" {
		b, err := hex.DecodeString(v)
		if err != nil {
			return nil, fmt.Errorf("bad IDPRIME_AID %q: %w", v, err)
		}
		h.aid = b
	}

	pin := os.Getenv("IDPRIME_PIN")
	if pin == "" {
		fmt.Fprint(os.Stderr, "IDPrime PIN: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("read PIN: %w", err)
		}
		pin = string(b)
	}
	h.pin = pin

	if certPath := os.Getenv("IDPRIME_CERT"); certPath != "" {
		k, err := h.loadExplicitKey(certPath)
		if err != nil {
			return nil, err
		}
		h.keys = []*idprimeKey{k}
		return h, nil
	}

	enum, err := h.autoEnumerate()
	if err != nil {
		return nil, err
	}
	if len(enum) == 0 {
		return nil, errors.New("idprime: no usable certificate on card (none with a matching on-card key, or all expired)")
	}
	h.keys = enum
	return h, nil
}

// loadExplicitKey builds a key from IDPRIME_CERT / IDPRIME_KEY_REF /
// IDPRIME_ALGO_REF. The key reference is read from the card via
// findKeyRefForCert if not overridden. The certificate may carry either
// an ECDSA or RSA public key.
func (h *IDPrime) loadExplicitKey(certPath string) (*idprimeKey, error) {
	cert, pub, err := loadSupportedLeaf(certPath)
	if err != nil {
		return nil, err
	}
	keyRef := byte(0)
	algoRef := byte(0)
	if v := os.Getenv("IDPRIME_KEY_REF"); v != "" {
		b, err := hex.DecodeString(v)
		if err != nil || len(b) != 1 {
			return nil, fmt.Errorf("bad IDPRIME_KEY_REF %q (want 2 hex chars)", v)
		}
		keyRef = b[0]
	}
	if v := os.Getenv("IDPRIME_ALGO_REF"); v != "" {
		b, err := hex.DecodeString(v)
		if err != nil || len(b) != 1 {
			return nil, fmt.Errorf("bad IDPRIME_ALGO_REF %q", v)
		}
		algoRef = b[0]
	}
	if keyRef == 0 {
		discovered, err := h.discoverKeyRef(cert)
		if err != nil {
			return nil, fmt.Errorf("discover key reference for %s: %w", certPath, err)
		}
		keyRef = discovered
	}
	if algoRef == 0 {
		if _, isRSA := pub.(*rsa.PublicKey); isRSA {
			algoRef = idprime.DefaultRSAAlgoRef
		} else {
			algoRef = idprime.DefaultAlgoRef
		}
	}
	return &idprimeKey{parent: h, cert: cert, pub: pub, keyRef: keyRef, algoRef: algoRef}, nil
}

// autoEnumerate walks the card and returns one idprimeKey per leaf
// cert (ECDSA or RSA) with a matching on-card private key and a current
// validity window. As a side effect, it caches the card's msroots chain
// bundle on h.intermediates so CertificateChain calls don't reopen the
// card.
func (h *IDPrime) autoEnumerate() ([]*idprimeKey, error) {
	var out []*idprimeKey
	err := h.withCard(func(card *idprime.Card) error {
		certs, err := card.EnumerateCerts()
		if err != nil {
			return err
		}
		// Best-effort: msroots may not exist on every card.
		if ints, err := card.ReadIntermediates(); err == nil {
			h.intermediates = ints
		}
		now := time.Now()
		allowExpired := os.Getenv("IDPRIME_ALLOW_EXPIRED") == "1"
		for _, ci := range certs {
			if !allowExpired && (now.Before(ci.Cert.NotBefore) || now.After(ci.Cert.NotAfter)) {
				continue
			}
			switch ci.Cert.PublicKey.(type) {
			case *ecdsa.PublicKey, *rsa.PublicKey:
				// supported
			default:
				continue
			}
			out = append(out, &idprimeKey{
				parent: h, cert: ci.Cert, pub: ci.Cert.PublicKey,
				keyRef: ci.KeyRef, algoRef: ci.AlgoRef,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// discoverKeyRef opens a PIN-less card session and asks the applet
// which on-card key reference matches the cert's public key. As a side
// effect, it caches the card's msroots chain bundle on h.intermediates.
func (h *IDPrime) discoverKeyRef(cert *x509.Certificate) (byte, error) {
	var ref byte
	err := h.withCard(func(card *idprime.Card) error {
		// EnumerateCerts already SELECTs the applet and performs the
		// findKeyRefForCert step internally, but we don't want to read
		// every kxc## file just to map one cert. Use the lower-level
		// path: SELECT applet, then probe.
		if err := card.SelectApplet(idprime.DefaultAID); err != nil {
			return err
		}
		// EnumerateCerts is the easiest path; just match by cert subject.
		certs, err := card.EnumerateCerts()
		if err != nil {
			return err
		}
		if ints, err := card.ReadIntermediates(); err == nil {
			h.intermediates = ints
		}
		for _, ci := range certs {
			if ci.Cert.Equal(cert) {
				ref = ci.KeyRef
				return nil
			}
		}
		return errors.New("certificate not present on card")
	})
	if err != nil {
		return 0, err
	}
	return ref, nil
}

// withCard runs fn inside a PC/SC card session (no PIN). The applet is
// not pre-SELECTed; callers do it (so they can override AID).
func (h *IDPrime) withCard(fn func(*idprime.Card) error) error {
	ctx, err := idprime.Connect()
	if err != nil {
		return err
	}
	defer ctx.Close()
	readerName, err := ctx.FindReader(h.reader)
	if err != nil {
		return err
	}
	card, err := ctx.Connect(readerName, idprime.ShareShared, idprime.ProtoAny)
	if err != nil {
		return err
	}
	defer card.Disconnect(idprime.LeaveCard)
	if err := card.BeginTransaction(); err != nil {
		return err
	}
	defer card.EndTransaction(idprime.LeaveCard)
	return fn(card)
}

func (h *IDPrime) Ready() bool { return len(h.keys) > 0 }

// RandomSource returns an io.Reader backed by the card's hardware RNG.
// Each Read opens a single card session and issues as many GET CHALLENGE
// commands as needed to fill the supplied buffer (256 bytes per APDU).
// No PIN is required — GET CHALLENGE is unauthenticated on IDPrime.
func (h *IDPrime) RandomSource() io.Reader { return &idprimeRand{parent: h} }

type idprimeRand struct {
	parent *IDPrime
}

func (r *idprimeRand) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	aid := r.parent.aid
	if aid == nil {
		aid = idprime.DefaultAID
	}
	var n int
	err := r.parent.withCard(func(card *idprime.Card) error {
		// IDPrime requires the crypto applet to be selected before
		// GET CHALLENGE will succeed.
		if err := card.SelectApplet(aid); err != nil {
			return err
		}
		// IDPrime accepts GET CHALLENGE Le ∈ {8, 16, 32}; larger or
		// off-size Le values return SW=6700 on the cards we've tested.
		// Always pull 32 at a time; trim the tail when the buffer
		// doesn't need a full 32.
		const chunk = 32
		for n < len(p) {
			got, err := card.GetChallenge(chunk)
			if err != nil {
				return err
			}
			take := len(got)
			if rem := len(p) - n; take > rem {
				take = rem
			}
			copy(p[n:], got[:take])
			n += take
		}
		return nil
	})
	return n, err
}

func (h *IDPrime) ListKeys() ([]Key, error) {
	out := make([]Key, 0, len(h.keys))
	for _, k := range h.keys {
		out = append(out, k)
	}
	return out, nil
}

func (h *IDPrime) ListKeysByName(name string) ([]Key, error) {
	var out []Key
	for _, k := range h.keys {
		if name == "" || name == k.cert.Subject.CommonName || name == k.cert.Subject.String() {
			out = append(out, k)
		}
	}
	return out, nil
}

func (h *IDPrime) PutCertificate(string, *x509.Certificate) error {
	return errors.New("idprime: PutCertificate is not supported (read-only HSM)")
}

func (h *IDPrime) GetCertificate(name string) (*x509.Certificate, error) {
	keys, err := h.ListKeysByName(name)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, os.ErrNotExist
	}
	return keys[0].(*idprimeKey).cert, nil
}

// idprimeKey is one Key entry — a single (cert, on-card key reference)
// pair. The underlying idprime.Signer is built lazily so we don't open
// the card until somebody actually signs. pub is the cert's public key
// and may be either *ecdsa.PublicKey or *rsa.PublicKey.
type idprimeKey struct {
	parent  *IDPrime
	cert    *x509.Certificate
	pub     crypto.PublicKey
	keyRef  byte
	algoRef byte

	once   sync.Once
	signer *idprime.Signer
	err    error
}

func (k *idprimeKey) ensureSigner() (*idprime.Signer, error) {
	k.once.Do(func() {
		k.signer, k.err = idprime.New(idprime.Config{
			Reader:  k.parent.reader,
			AID:     k.parent.aid,
			PIN:     k.parent.pin,
			KeyRef:  k.keyRef,
			AlgoRef: k.algoRef,
			Public:  k.pub,
		})
	})
	return k.signer, k.err
}

func (k *idprimeKey) Public() crypto.PublicKey { return k.pub }

func (k *idprimeKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s, err := k.ensureSigner()
	if err != nil {
		return nil, err
	}
	return s.Sign(rand, digest, opts)
}

func (k *idprimeKey) PublicBlob() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k.pub)
}

func (k *idprimeKey) Certificate() *x509.Certificate { return k.cert }

// CertificateChain returns the leaf certificate followed by any
// intermediates the card published via msroots. The slice is freshly
// allocated and safe for the caller to mutate.
func (k *idprimeKey) CertificateChain() []*x509.Certificate {
	if k.cert == nil {
		return nil
	}
	out := make([]*x509.Certificate, 0, 1+len(k.parent.intermediates))
	out = append(out, k.cert)
	out = append(out, k.parent.intermediates...)
	return out
}

func (k *idprimeKey) String() string {
	return fmt.Sprintf("IDPrime Key(cn=%q sn=%s keyRef=0x%02X algoRef=0x%02X notAfter=%s)",
		k.cert.Subject.CommonName,
		k.cert.SerialNumber.Text(16),
		k.keyRef, k.algoRef,
		k.cert.NotAfter.Format("2006-01-02"))
}

func loadSupportedLeaf(path string) (*x509.Certificate, crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, nil, fmt.Errorf("%s: no PEM block", path)
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: parse cert: %w", path, err)
	}
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		return cert, cert.PublicKey, nil
	default:
		return nil, nil, fmt.Errorf("%s: unsupported cert public key type %T", path, cert.PublicKey)
	}
}
