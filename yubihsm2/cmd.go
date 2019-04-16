package yubihsm2

import (
	"bytes"
	"errors"
	"os"
)

type CommandHandler func(command *Command) (*WireResponse, error)

func (c CommandHandler) Echo(payload []byte) ([]byte, error) {
	if len(payload) < 1 || len(payload) > 2021 {
		return nil, os.ErrInvalid
	}

	// simply send an echo request
	// https://developers.yubico.com/YubiHSM2/Commands/Echo.html
	command := NewCommand(CommandTypeEcho)
	command.Write(payload)

	resp, err := c(command)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(payload, resp.Payload) {
		return resp.Payload, errors.New("yubihsm2: response to echo isn't equal to original payload")
	}

	return resp.Payload, nil
}

func (c CommandHandler) CreateSession(keySetID uint16, hostChallenge []byte) (*CreateSessionResponse, error) {
	command := NewCommand(CommandTypeCreateSession)

	command.WriteValue(keySetID)
	command.Write(hostChallenge)

	resp, err := c(command)
	if err != nil {
		return nil, err
	}

	if resp.Len() != 17 {
		return nil, errors.New("invalid response payload length")
	}

	payload := resp.Payload

	return &CreateSessionResponse{
		SessionID:      uint8(payload[0]),
		CardChallenge:  payload[1:9],
		CardCryptogram: payload[9:],
	}, nil
}

func (c CommandHandler) AuthenticateSession(hostCryptogram []byte) error {
	command := NewCommand(CommandTypeAuthenticateSession)
	command.Write(hostCryptogram)

	_, err := c(command)

	return err
}
