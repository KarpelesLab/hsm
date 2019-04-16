package yubihsm2

import (
	"bytes"
	"errors"
	"io"
	"os"
)

type CommandHandler func(command *Command) (*WireResponse, error)

func (call CommandHandler) nullResponse(command *Command) error {
	_, err := call(command)
	return err
}

func (call CommandHandler) AuthenticateSession(hostCryptogram []byte) error {
	// https://developers.yubico.com/YubiHSM2/Commands/Authenticate_Session.html
	if len(hostCryptogram) != 17 {
		return os.ErrInvalid
	}

	command := NewCommand(CommandTypeAuthenticateSession)
	command.Write(hostCryptogram)
	return call.nullResponse(command)
}

func (call CommandHandler) Blink(secs uint8) error {
	// https://developers.yubico.com/YubiHSM2/Commands/Blink_Device.html
	command := NewCommand(CommandTypeSetBlink)
	command.WriteValue(secs)
	return call.nullResponse(command)
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
	return call.nullResponse(NewCommand(CommandTypeCloseSession))
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

func (call CommandHandler) DeviceInfo() (*DeviceInfoResponse, error) {
	resp, err := call(NewCommand(CommandTypeDeviceInfo))
	if err != nil {
		return nil, err
	}

	res := new(DeviceInfoResponse)
	resp.ReadValue(&res.VMajor)
	resp.ReadValue(&res.VMinor)
	resp.ReadValue(&res.VBuild)
	resp.ReadValue(&res.Serial)
	resp.ReadValue(&res.LogTotal)
	resp.ReadValue(&res.LogUsed)

	for {
		var a Algorithm
		err := resp.ReadValue((*uint8)(&a))
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		res.Algos = append(res.Algos, a)
	}

	return res, nil
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

func (call CommandHandler) ResetDevice() error {
	// https://developers.yubico.com/YubiHSM2/Commands/Reset_Device.html
	return call.nullResponse(NewCommand(CommandTypeReset))
}

func (call CommandHandler) GenerateAsymmetricKey(keyID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm) (uint16, error) {
	if len(label) > LabelLength {
		return 0, errors.New("label is too long")
	}
	if len(label) < LabelLength {
		label = append(label, bytes.Repeat([]byte{0x00}, LabelLength-len(label))...)
	}

	command := NewCommand(CommandTypeGenerateAsymmetricKey)
	command.WriteValue(keyID)
	command.Write(label)
	command.WriteValue(domains)
	command.WriteValue(capabilities)
	command.WriteValue(algorithm)

	resp, err := call(command)
	if err != nil {
		return 0, err
	}
	if resp.Len() != 2 {
		return 0, errors.New("invalid response payload length")
	}

	resp.ReadValue(&keyID)

	return keyID, nil
}

/*
func CreateSignDataEddsaCommand(keyID uint16, data []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeSignDataEddsa,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(data)

	command.Data = payload.Bytes()

	return command, nil
}

func CreateSignDataEcdsaCommand(keyID uint16, data []byte) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeSignDataEcdsa,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(data)

	command.Data = payload.Bytes()

	return command, nil
}

func CreatePutAsymmetricKeyCommand(keyID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm, keyPart1 []byte, keyPart2 []byte) (*CommandMessage, error) {
	if len(label) > LabelLength {
		return nil, errors.New("label is too long")
	}
	if len(label) < LabelLength {
		label = append(label, bytes.Repeat([]byte{0x00}, LabelLength-len(label))...)
	}
	command := &CommandMessage{
		CommandType: CommandTypePutAsymmetric,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	payload.Write(label)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	binary.Write(payload, binary.BigEndian, algorithm)
	payload.Write(keyPart1)
	if keyPart2 != nil {
		payload.Write(keyPart2)
	}

	command.Data = payload.Bytes()

	return command, nil
}

func CreateGetPubKeyCommand(keyID uint16) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeGetPubKey,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, keyID)
	command.Data = payload.Bytes()

	return command, nil
}

func CreateDeleteObjectCommand(objID uint16, objType uint8) (*CommandMessage, error) {
	command := &CommandMessage{
		CommandType: CommandTypeDeleteObject,
	}

	payload := bytes.NewBuffer([]byte{})
	binary.Write(payload, binary.BigEndian, objID)
	binary.Write(payload, binary.BigEndian, objType)
	command.Data = payload.Bytes()

	return command, nil
}

func CreateGenerateWrapKeyCommand(objectID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm, delegatedCapabilities uint64) (*CommandMessage, error) {
	if len(label) > LabelLength {
		return nil, errors.New("label is too long")
	}
	if len(label) < LabelLength {
		label = append(label, bytes.Repeat([]byte{0x00}, LabelLength-len(label))...)
	}
	command := &CommandMessage{
		CommandType: CommandTypeGenerateWrapKey,
	}

	payload := &bytes.Buffer{}
	binary.Write(payload, binary.BigEndian, objectID)
	payload.Write(label)
	binary.Write(payload, binary.BigEndian, domains)
	binary.Write(payload, binary.BigEndian, capabilities)
	binary.Write(payload, binary.BigEndian, algorithm)
	binary.Write(payload, binary.BigEndian, delegatedCapabilities)

	command.Data = payload.Bytes()

	return command, nil
}

func parseSignDataEddsaResponse(payload []byte) (Response, error) {
	return &SignDataEddsaResponse{
		Signature: payload,
	}, nil
}

func parseSignDataEcdsaResponse(payload []byte) (Response, error) {
	return &SignDataEcdsaResponse{
		Signature: payload,
	}, nil
}

func parsePutAsymmetricKeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var keyID uint16
	err := binary.Read(bytes.NewReader(payload), binary.BigEndian, &keyID)
	if err != nil {
		return nil, err
	}

	return &PutAsymmetricKeyResponse{
		KeyID: keyID,
	}, nil
}

func parseGetPubKeyResponse(payload []byte) (Response, error) {
	if len(payload) < 1 {
		return nil, errors.New("invalid response payload length")
	}
	return &GetPubKeyResponse{
		Algorithm: Algorithm(payload[0]),
		KeyData:   payload[1:],
	}, nil
}

func parseEchoResponse(payload []byte) (Response, error) {
	return &EchoResponse{
		Data: payload,
	}, nil
}
*/
