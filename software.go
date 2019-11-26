package hsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/boltdb/bolt"
)

type SoftwareHSM struct {
	db *bolt.DB
}

func NewSoftwareHSM() (*SoftwareHSM, error) {
	log.Printf("WARNING: You are running the HSM package in UNENCRYPTED software mode. DO NOT USE IN PRODUCTION")

	p := filepath.Join(globalSettingFolder, "hsm")
	os.MkdirAll(p, 0755)

	db, err := bolt.Open(filepath.Join(p, "hsmdata.db"), 0600, nil)
	if err != nil {
		return nil, err
	}

	r := &SoftwareHSM{db: db}

	return r, nil
}

type softwareKey struct {
	k []byte
	crypto.Signer
}

func (k *softwareKey) PublicBlob() ([]byte, error) {
	// grab public key & marshal
	return x509.MarshalPKIXPublicKey(k.Public())
}

func (k *softwareKey) String() string {
	return fmt.Sprintf("%T(%s)", k.Signer, k)
}

func (h *SoftwareHSM) Ready() bool {
	return h.db != nil
}

func (h *SoftwareHSM) ListKeys() ([]Key, error) {
	var list []Key
	// for all keys in db
	err := h.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("key"))
		if b == nil {
			return nil // empty list
		}

		// for each
		return b.ForEach(func(k, v []byte) error {
			// we don't care about k
			keyI, err := x509.ParsePKCS8PrivateKey(v)
			if err != nil {
				return err
			}

			switch key := keyI.(type) {
			case *rsa.PrivateKey:
				list = append(list, &softwareKey{k, key})
			case *ecdsa.PrivateKey:
				list = append(list, &softwareKey{k, key})
			case ed25519.PrivateKey:
				list = append(list, &softwareKey{k, key})
			}
			return nil
		})
	})
	return list, err
}

func (h *SoftwareHSM) ListKeysByName(name string) ([]Key, error) {
	// TODO
	return nil, nil
}

func (h *SoftwareHSM) PutCertificate(name string, cert *x509.Certificate) error {
	if cert.Raw == nil {
		return errors.New("certificate is not valid (missing Raw data)")
	}

	return h.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("crt"))
		if err != nil {
			return err
		}

		return b.Put([]byte(name), cert.Raw)
	})
}

func (h *SoftwareHSM) GetCertificate(name string) (*x509.Certificate, error) {
	var crt *x509.Certificate
	err := h.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("crt"))
		if b == nil {
			return os.ErrNotExist
		}

		// get
		v := b.Get([]byte(name))
		if v == nil {
			return os.ErrNotExist
		}

		// parse
		c, err := x509.ParseCertificate(v)
		if err != nil {
			return err
		}
		crt = c
		return nil
	})
	return crt, err
}
