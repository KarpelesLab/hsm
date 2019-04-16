package hsm

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"syscall"

	"github.com/MagicalTux/hsm/yubihsm2"
	"golang.org/x/crypto/ssh/terminal"
)

func NewYubiHSM2() (HSM, error) {
	fmt.Print("Enter YubiHSM2 Passphrase: ")
	pwd, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}
	fmt.Printf("\n")

	c := yubihsm2.NewHTTPConnector("localhost:12345")
	sm, err := yubihsm2.NewSessionManager(c, 1, string(pwd))
	if err != nil {
		return nil, err
	}

	log.Printf("sending echo")
	echoMessage := []byte("test")
	command, err := yubihsm2.CreateEchoCommand(echoMessage)
	if err != nil {
		return nil, err
	}

	resp, err := sm.SendEncryptedCommand(command)
	if err != nil {
		return nil, err
	}

	parsedResp, matched := resp.(*yubihsm2.EchoResponse)
	if !matched {
		return nil, errors.New("invalid response")
	}

	if bytes.Equal(parsedResp.Data, echoMessage) {
		log.Printf("success")
	}

	return sm, nil
}
