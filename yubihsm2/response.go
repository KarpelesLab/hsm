package yubihsm2

type (
	CreateSessionResponse struct {
		SessionID      uint8
		CardChallenge  []byte
		CardCryptogram []byte
	}

	SessionMessageResponse struct {
		SessionID     uint8
		EncryptedData []byte
		MAC           []byte
	}

	DeviceInfoResponse struct {
		VMajor   uint8
		VMinor   uint8
		VBuild   uint8
		Serial   uint32
		LogTotal uint8
		LogUsed  uint8
		Algos    []Algorithm
	}

	GetPubKeyResponse struct {
		Algorithm Algorithm
		// KeyData can contain different formats depending on the algorithm according to the YubiHSM2 documentation.
		KeyData []byte
	}
)

/*
func parseCreateAsymmetricKeyResponse(payload []byte) (Response, error) {
	if len(payload) != 2 {
		return nil, errors.New("invalid response payload length")
	}

	var keyID uint16
	err := binary.Read(bytes.NewReader(payload[1:3]), binary.BigEndian, &keyID)
	if err != nil {
		return nil, err
	}

	return &CreateAsymmetricKeyResponse{
		KeyID: keyID,
	}, nil
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
