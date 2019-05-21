package hsm

import (
	"crypto"
	"crypto/ecdsa"
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
	"syscall"

	"github.com/MagicalTux/hsm/yubihsm2"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh/terminal"
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

func NewYubiHSM2() (HSM, error) {
	c := yubihsm2.NewHTTPConnector("localhost:12345")
	status, err := c.GetStatus()
	if err != nil {
		return nil, err
	}
	log.Printf("Connected to YubiHSM manager v%s", status.Version)
	if status.Status != "OK" {
		log.Printf("Key status invalid: %s", status.Status)
		return nil, fmt.Errorf("unable to access key: %s", status.Status)
	}

	fmt.Print("Enter YubiHSM2 for Key 1 Passphrase: ")
	pwd, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}
	fmt.Printf("\n")

	sm, err := yubihsm2.NewSessionManager(c, 1, string(pwd))
	if err != nil {
		return nil, err
	}

	return &YubiHSM2{sm}, nil
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
	res, err := h.sm.ListObjects(yubihsm2.TypeOpaque, yubihsm2.Label(name))
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
	res, err := h.sm.ListObjects(yubihsm2.TypeOpaque, yubihsm2.Label(name))
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

func (k *YubiHSM2Key) Public() crypto.PublicKey {
	key, err := k.parent.sm.GetPubKey(k.kid)
	if err != nil {
		return nil
	}

	switch key.Algorithm {
	case yubihsm2.Ed25519:
		return ed25519.PublicKey(key.KeyData)
	case yubihsm2.Secp256r1:
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(key.KeyData[:32]),
			Y:     new(big.Int).SetBytes(key.KeyData[32:]),
		}
	case yubihsm2.Secp384r1:
		return &ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     new(big.Int).SetBytes(key.KeyData[:48]),
			Y:     new(big.Int).SetBytes(key.KeyData[48:]),
		}
	case yubihsm2.Secp521r1:
		// key size, 64 or 66?
		return &ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     new(big.Int).SetBytes(key.KeyData[:66]),
			Y:     new(big.Int).SetBytes(key.KeyData[66:]),
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

func (k *YubiHSM2Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	k.getInfo.Do(k.doGetInfo)

	switch k.info.Algorithm {
	case yubihsm2.Ed25519:
		if opts.HashFunc() != crypto.Hash(0) {
			return nil, errors.New("ed25519: cannot sign hashed message")
		}

		if len(digest) > 2000 { // give or take
			return nil, errors.New("ed25519: message too large")
		}

		return k.parent.sm.SignDataEddsa(k.kid, digest)
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
