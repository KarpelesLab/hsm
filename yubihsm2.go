package hsm

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"log"
	"syscall"

	"github.com/MagicalTux/hsm/yubihsm2"
	"golang.org/x/crypto/ssh/terminal"
)

type YubiHSM2 struct {
	sm *yubihsm2.SessionManager
}

type YubiHSM2Key struct {
	parent *YubiHSM2
	kid    uint16
}

func NewYubiHSM2() (HSM, error) {
	c := yubihsm2.NewHTTPConnector("localhost:12345")
	status, err := c.GetStatus()
	if err != nil {
		return nil, err
	}
	log.Printf("Connected to YubiHSM manager v%s", status.Version)

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

func (k *YubiHSM2Key) Public() crypto.PublicKey {
	return k
}

func (k *YubiHSM2Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// generate hash
	var hash []byte

	switch opts.HashFunc() {
	case crypto.SHA1:
	case crypto.SHA256:
	case crypto.SHA384:
	case crypto.SHA512:
	}

	h := opts.HashFunc().New()
	h.Write(hash)
	hash = h.Sum(nil)

	// Depend on type of key!
	return nil, errors.New("todo")
}

func (k *YubiHSM2Key) String() string {
	return fmt.Sprintf("YubiHSM2 Key(0x%x)", k.kid)
}
