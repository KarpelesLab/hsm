package hsm

import (
	"errors"
	"os"
)

func New() (HSM, error) {
	// look into env variable HSM
	switch os.Getenv("HSM") {
	case "software":
		return NewSoftwareHSM()
	case "yubihsm2":
		return NewYubiHSM2()
	case "idprime":
		return NewIDPrime()
	}

	return nil, errors.New("no HSM enabled, please run with HSM env variable")
}
