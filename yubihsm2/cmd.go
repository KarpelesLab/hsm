package yubihsm2

import (
	"bytes"
	"errors"
	"io"
	"os"
)

type CommandHandler func(command *Command) (*WireResponse, error)

func (call CommandHandler) nullResponse(command *Command, err error) error {
	if err != nil {
		return err
	}
	_, err = call(command)
	return err
}

func (call CommandHandler) AuthenticateSession(hostCryptogram []byte) error {
	// https://developers.yubico.com/YubiHSM2/Commands/Authenticate_Session.html
	if len(hostCryptogram) != 8 {
		return errors.New("AuthenticateSession: invalid length for hostCryptogram")
	}

	return call.nullResponse(CmdAuthenticateSession.Build(hostCryptogram))
}

func (call CommandHandler) Blink(secs uint8) error {
	// https://developers.yubico.com/YubiHSM2/Commands/Blink_Device.html
	return call.nullResponse(CmdSetBlink.Build(secs))
}

func (call CommandHandler) ChangeAuthKey(objectId uint16, algo Algorithm, encKey, macKey []byte) (uint16, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Change_Authentication_Key.html
	if len(encKey) != 16 || len(macKey) != 16 {
		return 0, os.ErrInvalid
	}

	command, err := CmdChangeAuthKey.Build(objectId, algo, encKey, macKey)
	if err != nil {
		return 0, nil
	}

	res, err := call(command)
	if err != nil {
		return 0, nil
	}
	if res.Len() != 2 {
		return 0, errors.New("ChangeAuthKey: expected exactly 2 bytes payload")
	}

	res.ReadValue(&objectId)
	return objectId, nil
}

func (call CommandHandler) CloseSession() error {
	// https://developers.yubico.com/YubiHSM2/Commands/Close_Session.html
	return call.nullResponse(CmdCloseSession.New(), nil)
}

// Create Otp Aead

func (call CommandHandler) CreateSession(keySetID uint16, hostChallenge []byte) (*CreateSessionResponse, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html
	command, err := CmdCreateSession.Build(keySetID, hostChallenge)
	if err != nil {
		return nil, err
	}

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
	return call.nullResponse(CmdDeleteObject.Build(objID, objType))
}

// Derive Ecdh

func (call CommandHandler) DeviceInfo() (*DeviceInfoResponse, error) {
	resp, err := call(CmdDeviceInfo.New())
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

	command, err := CmdEcho.Build(payload)
	if err != nil {
		return nil, err
	}

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

	command := CmdGenerateAsymmetricKey.New()
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

func (call CommandHandler) GetObjectInfo(objectID ObjectID, typ ObjectType) (*ObjectInfoResponse, error) {
	command, err := CmdGetObjectInfo.Build(objectID, typ)
	if err != nil {
		return nil, err
	}

	res, err := call(command)
	if err != nil {
		return nil, err
	}

	obj := new(ObjectInfoResponse)

	res.ReadValue(&obj.Capabilities)
	res.ReadValue(&obj.ObjectID)
	res.ReadValue(&obj.ObjectLength)
	res.ReadValue(&obj.Domains)
	res.ReadValue(&obj.Type)
	res.ReadValue(&obj.Algorithm)
	res.ReadValue(&obj.Sequence)
	res.ReadValue(&obj.Origin)

	lbl := make([]byte, 40)
	res.Read(lbl)
	obj.Label = bytes.TrimRight(lbl, "\x00")

	res.ReadValue(&obj.DelegatedCap)

	return obj, nil
}

func (call CommandHandler) GetPseudoRandom(l uint16) ([]byte, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Get_Pseudo_Random.html
	command := CmdGetPseudoRandom.New()
	command.WriteValue(l)

	res, err := call(command)
	if err != nil {
		return nil, err
	}

	return res.Payload, nil
}

func (call CommandHandler) GetPubKey(keyID ObjectID) (*GetPubKeyResponse, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Get_Public_Key.html
	command := CmdGetPubKey.New()
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

	command := CmdGenerateWrapKey.New()
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
	command := CmdListObjects.New()

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
	return call.nullResponse(CmdReset.New(), nil)
}

func (call CommandHandler) SignDataEddsa(keyID ObjectID, data []byte) ([]byte, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Sign_Eddsa.html
	command := CmdSignDataEddsa.New()
	command.WriteValue(keyID)
	command.Write(data)

	res, err := call(command)
	if err != nil {
		return nil, err
	}

	return res.Payload, nil
}

func (call CommandHandler) SignDataEcdsa(keyID ObjectID, data []byte) ([]byte, error) {
	// https://developers.yubico.com/YubiHSM2/Commands/Sign_Ecdsa.html
	command := CmdSignDataEcdsa.New()
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

	command := CmdPutAsymmetric.New()
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
