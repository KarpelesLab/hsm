package hsm

import (
	"crypto"
	"crypto/ecdsa"
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
//	IDPRIME_ALGO_REF   optional override, hex byte. Default 54 (ECDSA).
type IDPrime struct {
	reader string
	pin    string
	aid    []byte
	keys   []*idprimeKey
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
// findKeyRefForCert if not overridden.
func (h *IDPrime) loadExplicitKey(certPath string) (*idprimeKey, error) {
	cert, pub, err := loadEcdsaLeaf(certPath)
	if err != nil {
		return nil, err
	}
	keyRef := byte(0)
	algoRef := idprime.DefaultAlgoRef
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
	return &idprimeKey{parent: h, cert: cert, pub: pub, keyRef: keyRef, algoRef: algoRef}, nil
}

// autoEnumerate walks the card and returns one idprimeKey per ECDSA
// leaf cert with a matching on-card private key and a current validity
// window.
func (h *IDPrime) autoEnumerate() ([]*idprimeKey, error) {
	var out []*idprimeKey
	err := h.withCard(func(card *idprime.Card) error {
		certs, err := card.EnumerateCerts()
		if err != nil {
			return err
		}
		now := time.Now()
		for _, ci := range certs {
			if now.Before(ci.Cert.NotBefore) || now.After(ci.Cert.NotAfter) {
				continue
			}
			pub, ok := ci.Cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				continue // Signer is ECDSA-only for now
			}
			out = append(out, &idprimeKey{
				parent: h, cert: ci.Cert, pub: pub,
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
// which on-card key reference matches the cert's public key.
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
// the card until somebody actually signs.
type idprimeKey struct {
	parent  *IDPrime
	cert    *x509.Certificate
	pub     *ecdsa.PublicKey
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

func (k *idprimeKey) String() string {
	return fmt.Sprintf("IDPrime Key(cn=%q sn=%s keyRef=0x%02X algoRef=0x%02X notAfter=%s)",
		k.cert.Subject.CommonName,
		k.cert.SerialNumber.Text(16),
		k.keyRef, k.algoRef,
		k.cert.NotAfter.Format("2006-01-02"))
}

func loadEcdsaLeaf(path string) (*x509.Certificate, *ecdsa.PublicKey, error) {
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
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("%s: not an ECDSA cert (got %T)", path, cert.PublicKey)
	}
	return cert, pub, nil
}
