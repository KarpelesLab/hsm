package hsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"sync"

	"github.com/KarpelesLab/hsm/yubihsm2"
	"golang.org/x/term"
)

type YubiHSM2 struct {
	sm *yubihsm2.SessionManager
}

type YubiHSM2Key struct {
	parent *YubiHSM2
	kid    yubihsm2.ObjectID

	info    *yubihsm2.ObjectInfoResponse
	getInfo sync.Once
}

// Default YubiHSM2 connector address
const defaultYubiHSM2Address = "localhost:12345"

func NewYubiHSM2() (HSM, error) {
	addr := os.Getenv("YUBIHSM2_ADDR")
	if addr == "" {
		addr = defaultYubiHSM2Address
	}

	c := yubihsm2.NewHTTPConnector(addr)
	status, err := c.GetStatus()
	if err != nil {
		return nil, err
	}
	log.Printf("Connected to YubiHSM manager v%s", status.Version)
	if status.Status != "OK" {
		log.Printf("Key status invalid: %s", status.Status)
		return nil, fmt.Errorf("unable to access key: %s", status.Status)
	}

	attempt := 1
	for {
		fmt.Print("Enter passphrase for YubiHSM2 Key 1: ")
		pwd, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			// failed to read from terminal → fail now
			return nil, err
		}
		fmt.Printf("\n")

		sm, err := yubihsm2.NewSessionManager(c, 1, string(pwd))
		if err != nil {
			fmt.Printf("Failed to unlock YubiHSM2: %s\n", err)
			attempt += 1
			if attempt <= 3 {
				continue
			}
			return nil, err
		}

		return &YubiHSM2{sm}, nil
	}
}

// Close destroys the session manager and releases resources
func (h *YubiHSM2) Close() {
	if h.sm != nil {
		h.sm.Destroy()
	}
}

func (h *YubiHSM2) Ready() bool {
	return h.sm != nil
}

func (h *YubiHSM2) ListKeys() ([]Key, error) {
	res, err := h.sm.ListObjects(yubihsm2.AsymmetricKey)
	if err != nil {
		return nil, err
	}
	var f []Key
	for _, i := range res {
		f = append(f, &YubiHSM2Key{parent: h, kid: i.ObjectID})
	}
	return f, nil
}

func (h *YubiHSM2) ListKeysByName(name string) ([]Key, error) {
	res, err := h.sm.ListObjects(yubihsm2.AsymmetricKey, yubihsm2.Label(name))
	if err != nil {
		return nil, err
	}
	var f []Key
	for _, i := range res {
		f = append(f, &YubiHSM2Key{parent: h, kid: i.ObjectID})
	}
	return f, nil
}

func (h *YubiHSM2) PutCertificate(name string, cert *x509.Certificate) error {
	res, err := h.sm.ListObjects(yubihsm2.TypeOpaque, yubihsm2.OpaqueX509Cert, yubihsm2.Label(name))
	if err != nil {
		return err
	}
	var id yubihsm2.ObjectID

	if len(res) > 0 {
		id = res[0].ObjectID
	}

	// send certificate
	_, err = h.sm.PutOpaque(id, []byte(name), 1, 0, yubihsm2.OpaqueX509Cert, cert.Raw)
	return err
}

func (h *YubiHSM2) GetCertificate(name string) (*x509.Certificate, error) {
	res, err := h.sm.ListObjects(yubihsm2.TypeOpaque, yubihsm2.OpaqueX509Cert, yubihsm2.Label(name))
	if err != nil {
		return nil, err
	}
	if len(res) == 0 {
		return nil, os.ErrNotExist
	}

	// grab data
	der, err := h.sm.GetOpaque(res[0].ObjectID)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// ECDSA key sizes in bytes for each curve
const (
	ecdsaP256KeySize = 32
	ecdsaP384KeySize = 48
	ecdsaP521KeySize = 66
	ed25519KeySize   = 32
)

func (k *YubiHSM2Key) Public() crypto.PublicKey {
	key, err := k.parent.sm.GetPubKey(k.kid)
	if err != nil {
		return nil
	}

	switch key.Algorithm {
	case yubihsm2.Ed25519:
		if len(key.KeyData) < ed25519KeySize {
			return nil
		}
		return ed25519.PublicKey(key.KeyData)
	case yubihsm2.Secp256r1:
		if len(key.KeyData) < ecdsaP256KeySize*2 {
			return nil
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(key.KeyData[:ecdsaP256KeySize]),
			Y:     new(big.Int).SetBytes(key.KeyData[ecdsaP256KeySize : ecdsaP256KeySize*2]),
		}
	case yubihsm2.Secp384r1:
		if len(key.KeyData) < ecdsaP384KeySize*2 {
			return nil
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     new(big.Int).SetBytes(key.KeyData[:ecdsaP384KeySize]),
			Y:     new(big.Int).SetBytes(key.KeyData[ecdsaP384KeySize : ecdsaP384KeySize*2]),
		}
	case yubihsm2.Secp521r1:
		if len(key.KeyData) < ecdsaP521KeySize*2 {
			return nil
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     new(big.Int).SetBytes(key.KeyData[:ecdsaP521KeySize]),
			Y:     new(big.Int).SetBytes(key.KeyData[ecdsaP521KeySize : ecdsaP521KeySize*2]),
		}
	case yubihsm2.Rsa2048, yubihsm2.Rsa3072, yubihsm2.Rsa4096:
		return &rsa.PublicKey{
			N: big.NewInt(0).SetBytes(key.KeyData),
			E: 65537, // YubiHSM2 has a fixed value for RSA e
		}
	default:
		return key.KeyData
	}
}

// MaxEdDSAMessageSize is the approximate maximum message size for EdDSA signing
const MaxEdDSAMessageSize = 2000

// Sign signs digest with the private key held in the HSM.
// The rand parameter is unused as the HSM provides its own randomness.
func (k *YubiHSM2Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	k.getInfo.Do(k.doGetInfo)

	switch k.info.Algorithm {
	case yubihsm2.Ed25519:
		if opts.HashFunc() != crypto.Hash(0) {
			return nil, errors.New("ed25519: cannot sign hashed message")
		}

		if len(digest) > MaxEdDSAMessageSize {
			return nil, errors.New("ed25519: message too large")
		}

		return k.parent.sm.SignDataEddsa(k.kid, digest)
	case yubihsm2.Secp256r1, yubihsm2.Secp384r1, yubihsm2.Secp521r1:
		return k.parent.sm.SignDataEcdsa(k.kid, digest)
	case yubihsm2.Rsa2048, yubihsm2.Rsa3072, yubihsm2.Rsa4096:
		if pssO, ok := opts.(*rsa.PSSOptions); ok {
			// this uses PSS. Algo needs to match the current algo
			var algo yubihsm2.Algorithm
			switch pssO.Hash {
			case crypto.SHA1:
				algo = yubihsm2.RsaPssSha1
			case crypto.SHA256:
				algo = yubihsm2.RsaPssSha256
			case crypto.SHA384:
				algo = yubihsm2.RsaPssSha384
			case crypto.SHA512:
				algo = yubihsm2.RsaPssSha512
			default:
				return nil, errors.New("unsupported hashing algorithm")
			}
			return k.parent.sm.SignDataPss(k.kid, algo, uint16(pssO.SaltLength), digest)
		}
		return k.parent.sm.SignDataPkcs1(k.kid, digest)
	}

	// Depend on type of key!
	return nil, errors.New("todo")
}

func (k *YubiHSM2Key) String() string {
	k.getInfo.Do(k.doGetInfo)
	return fmt.Sprintf("YubiHSM2 Key(0x%x Cap=0x%x Algo=%s Label=%s)", k.kid, k.info.Capabilities, k.info.Algorithm.String(), k.info.Label)
}

func (k *YubiHSM2Key) doGetInfo() {
	// grab info from yubihsm
	info, err := k.parent.sm.GetObjectInfo(k.kid, yubihsm2.AsymmetricKey)
	if err != nil {
		log.Printf("Get info failed: %s", err)
		k.info = &yubihsm2.ObjectInfoResponse{}
	} else {
		k.info = info
	}
}

func (k *YubiHSM2Key) PublicBlob() ([]byte, error) {
	key, err := k.parent.sm.GetPubKey(k.kid)
	if err != nil {
		return nil, err
	}

	// we have key.Algorithm too
	return key.KeyData, nil
}
