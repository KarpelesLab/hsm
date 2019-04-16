package hsm

import (
	"fmt"
	"log"
	"syscall"

	"github.com/MagicalTux/hsm/yubihsm2"
	"golang.org/x/crypto/ssh/terminal"
)

type YubiHSM2 struct {
	sm *yubihsm2.SessionManager
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

	log.Printf("sending echo")
	echoMessage := []byte("test")
	res, err := sm.Echo(echoMessage)
	if err != nil {
		return nil, err
	}

	log.Printf("success: %s", res)

	return &YubiHSM2{sm}, nil
}

func (h *YubiHSM2) Ready() bool {
	return h.sm != nil
}
