package hsm

import (
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

func (h *SoftwareHSM) Ready() bool {
	return h.db != nil
}

func (h *SoftwareHSM) ListKeys() ([]Key, error) {
	// TODO
	return nil, nil
}

func (h *SoftwareHSM) ListKeysByName(name string) ([]Key, error) {
	// TODO
	return nil, nil
}
