package yubihsm2

import (
	"bytes"
	"errors"
	"os"
)

func (s *SessionManager) Echo(payload []byte) ([]byte, error) {
	if len(payload) < 1 || len(payload) > 2021 {
		return nil, os.ErrInvalid
	}

	// simply send an echo request
	// https://developers.yubico.com/YubiHSM2/Commands/Echo.html
	command := NewCommand(CommandTypeEcho)
	command.Write(payload)

	resp, err := s.SendEncryptedCommand(command)
	if err != nil {
		return nil, err
	}

	err = resp.Expect(CommandTypeEcho)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(payload, resp.Payload) {
		return resp.Payload, errors.New("yubihsm2: response to echo isn't equal to original payload")
	}

	return resp.Payload, nil
}
