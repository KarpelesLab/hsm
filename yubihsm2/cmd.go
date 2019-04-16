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
	if len(hostCryptogram) != 8 {
		return errors.New("AuthenticateSession: invalid length for hostCryptogram")
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

// Create Otp Aead

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

// Decrypt Oaep
// Decrypt Otp
// Decrypt Pkcs1

func (call CommandHandler) DeleteObject(objID uint16, objType uint8) error {
	// https://developers.yubico.com/YubiHSM2/Commands/Delete_Object.html
	command := NewCommand(CommandTypeDeleteObject)

	command.WriteValue(objID)
	command.WriteValue(objType)

	return call.nullResponse(command)
}

// Derive Ecdh

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

func (call CommandHandler) GetPseudoRandom(l uint16) ([]byte, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Get_Pseudo_Random.html
	command := NewCommand(CommandTypeGetPseudoRandom)
	command.WriteValue(l)

	res, err := call(command)
	if err != nil {
		return nil, err
	}

	return res.Payload, nil
}

func (call CommandHandler) GetPubKey(keyID uint16) (*GetPubKeyResponse, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Get_Public_Key.html
	command := NewCommand(CommandTypeGetPubKey)
	command.WriteValue(keyID)

	res, err := call(command)
	if err != nil {
		return nil, err
	}
	if res.Len() < 1 {
		return nil, errors.New("invalid response payload length")
	}

	obj := &GetPubKeyResponse{
		Algorithm: Algorithm(res.Payload[0]),
		KeyData:   res.Payload[1:],
	}
	return obj, nil
}

func (call CommandHandler) GenerateWrapKey(objectID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm, delegatedCapabilities uint64) (uint16, error) {
	if len(label) > LabelLength {
		return 0, errors.New("label is too long")
	}
	if len(label) < LabelLength {
		label = append(label, bytes.Repeat([]byte{0x00}, LabelLength-len(label))...)
	}

	command := NewCommand(CommandTypeGenerateWrapKey)
	command.WriteValue(objectID)
	command.Write(label)
	command.WriteValue(domains)
	command.WriteValue(capabilities)
	command.WriteValue(uint8(algorithm))
	command.WriteValue(delegatedCapabilities)

	res, err := call(command)
	if err != nil {
		return 0, err
	}
	if res.Len() != 2 {
		return 0, errors.New("invalid response payload length")
	}
	res.ReadValue(&objectID)
	return objectID, nil
}

func (call CommandHandler) ListObjects(filters ...interface{}) ([]*ListObjectsResponse, error) {
	command := NewCommand(CommandTypeListObjects)

	for _, f := range filters {
		switch v := f.(type) {
		case ObjectID:
			command.WriteValue(uint8(0x01))
			command.WriteValue(uint16(v))
		case ObjectType:
			command.WriteValue(uint8(0x02))
			command.WriteValue(uint8(v))
		case Domain:
			command.WriteValue(uint8(0x03))
			command.WriteValue(uint16(v))
		case Capability:
			command.WriteValue(uint8(0x04))
			command.WriteValue(uint64(v))
		case Algorithm:
			command.WriteValue(uint8(0x05))
			command.WriteValue(uint8(v))
		case Label:
			command.WriteValue(uint8(0x06))
			if err := writeLabel(command, v); err != nil {
				return nil, err
			}
		}
	}

	res, err := call(command)

	var ret []*ListObjectsResponse

	for {
		v := new(ListObjectsResponse)
		err = res.ReadValue((*uint16)(&v.ObjectID))
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		err = res.ReadValue((*uint8)(&v.Type))
		if err != nil {
			return nil, err
		}
		err = res.ReadValue(&v.Sequence)
		if err != nil {
			return nil, err
		}

		ret = append(ret, v)
	}

	return ret, nil
}

func (call CommandHandler) ResetDevice() error {
	// https://developers.yubico.com/YubiHSM2/Commands/Reset_Device.html
	return call.nullResponse(NewCommand(CommandTypeReset))
}

func (call CommandHandler) SignDataEddsa(keyID uint16, data []byte) ([]byte, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Sign_Eddsa.html
	command := NewCommand(CommandTypeSignDataEddsa)
	command.WriteValue(keyID)
	command.Write(data)

	res, err := call(command)
	if err != nil {
		return nil, err
	}

	return res.Payload, nil
}

func (call CommandHandler) SignDataEcdsa(keyID uint16, data []byte) ([]byte, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Sign_Ecdsa.html
	command := NewCommand(CommandTypeSignDataEcdsa)
	command.WriteValue(keyID)
	command.Write(data)

	res, err := call(command)
	if err != nil {
		return nil, err
	}

	return res.Payload, nil
}

func (call CommandHandler) PutAsymmetricKey(keyID uint16, label []byte, domains uint16, capabilities uint64, algorithm Algorithm, keyPart1 []byte, keyPart2 []byte) (uint16, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Put_Asymmetric_Key.html
	if len(label) > LabelLength {
		return 0, errors.New("label is too long")
	}
	if len(label) < LabelLength {
		label = append(label, bytes.Repeat([]byte{0x00}, LabelLength-len(label))...)
	}

	command := NewCommand(CommandTypePutAsymmetric)
	command.WriteValue(keyID)
	command.Write(label)
	command.WriteValue(domains)
	command.WriteValue(capabilities)
	command.WriteValue(algorithm)
	command.Write(keyPart1)
	if keyPart2 != nil {
		command.Write(keyPart2)
	}

	res, err := call(command)
	if err != nil {
		return 0, err
	}
	if res.Len() != 2 {
		return 0, errors.New("invalid response payload length")
	}
	res.ReadValue(&keyID)
	return keyID, nil
}
