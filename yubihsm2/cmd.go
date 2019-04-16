package yubihsm2

import (
	"bytes"
	"errors"
	"os"
)

type CommandHandler func(command *Command) (*WireResponse, error)

func (call CommandHandler) AuthenticateSession(hostCryptogram []byte) error {
	// https://developers.yubico.com/YubiHSM2/Commands/Authenticate_Session.html
	if len(hostCryptogram) != 17 {
		return os.ErrInvalid
	}

	command := NewCommand(CommandTypeAuthenticateSession)
	command.Write(hostCryptogram)

	_, err := call(command)

	return err
}

func (call CommandHandler) Blink(secs uint8) error {
	// https://developers.yubico.com/YubiHSM2/Commands/Blink_Device.html
	command := NewCommand(CommandTypeSetBlink)
	command.WriteValue(secs)

	_, err := call(command)
	return err
}

func (call CommandHandler) ChangeAuthKey(objectId uint16, algo Algorithm, encKey, macKey []byte) (uint16, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Change_Authentication_Key.html
	if len(encKey) != 16 || len(macKey) != 16 {
		return 0, os.ErrInvalid
	}

	command := NewCommand(CommandTypeChangeAuthKey)
	command.WriteValue(objectId)
	command.WriteValue(uint8(algo))
	command.Write(encKey)
	command.Write(macKey)

	res, err := call(command)
	if err != nil {
		return 0, nil
	}
	if res.Len() != 2 {
		return 0, errors.New("ChangeAuthKey: expected exactly 2 bytes payload")
	}

	var resObjectId uint16
	res.ReadValue(&resObjectId)
	return resObjectId, nil
}

func (call CommandHandler) CloseSession() error {
	// https://developers.yubico.com/YubiHSM2/Commands/Close_Session.html
	_, err := call(NewCommand(CommandTypeCloseSession))
	return err
}

func (call CommandHandler) CreateSession(keySetID uint16, hostChallenge []byte) (*CreateSessionResponse, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html
	command := NewCommand(CommandTypeCreateSession)

	command.WriteValue(keySetID)
	command.Write(hostChallenge)

	resp, err := call(command)
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

func (call CommandHandler) Echo(payload []byte) ([]byte, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Echo.html
	if len(payload) < 1 || len(payload) > 2021 {
		return nil, os.ErrInvalid
	}

	command := NewCommand(CommandTypeEcho)
	command.Write(payload)

	resp, err := call(command)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(payload, resp.Payload) {
		return resp.Payload, errors.New("yubihsm2: response to echo isn't equal to original payload")
	}

	return resp.Payload, nil
}
