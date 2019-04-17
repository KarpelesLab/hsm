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

	ListObjectsResponse struct {
		ObjectID uint16
		Type     ObjectType
		Sequence uint8
	}

	ObjectInfoResponse struct {
		Capabilities Capability
		ObjectID     ObjectID
		ObjectLength uint16
		Domains      Domain
		Type         ObjectType
		Algorithm    Algorithm
		Sequence     uint8
		Origin       uint8
		Label        []byte
		DelegatedCap Capability
	}
)
