package yubihsm2

import "errors"

type (
	CommandType uint8
	ErrorCode   uint8
	ObjectType  uint8
	ObjectID    uint16
	Domain      uint16
	Label       []byte
	Capability  uint64
)

var (
	ErrInvalidResponseType = errors.New("yubihsm2: response has invalid type")
)

//go:generate stringer -type=Capability,ErrorCode,CommandType,ObjectType,Domain -output types_s.go

const (
	ResponseCommandOffset = 0x80
	ErrorResponseCode     = 0xff

	// LabelLength is the max length of a label
	LabelLength = 40

	CmdEcho                  CommandType = 0x01
	CmdCreateSession         CommandType = 0x03
	CmdAuthenticateSession   CommandType = 0x04
	CmdSessionMessage        CommandType = 0x05
	CmdDeviceInfo            CommandType = 0x06
	CmdReset                 CommandType = 0x08
	CmdCloseSession          CommandType = 0x40
	CmdStorageStatus         CommandType = 0x41
	CmdPutOpaque             CommandType = 0x42
	CmdGetOpaque             CommandType = 0x43
	CmdPutAuthKey            CommandType = 0x44
	CmdPutAsymmetric         CommandType = 0x45
	CmdGenerateAsymmetricKey CommandType = 0x46
	CmdSignDataPkcs1         CommandType = 0x47
	CmdListObjects           CommandType = 0x48
	CmdDecryptPkcs1          CommandType = 0x49
	CmdExportWrapped         CommandType = 0x4a
	CmdImportWrapped         CommandType = 0x4b
	CmdPutWrapKey            CommandType = 0x4c
	CmdGetLogs               CommandType = 0x4d
	CmdGetObjectInfo         CommandType = 0x4e
	CmdPutOption             CommandType = 0x4f
	CmdGetOption             CommandType = 0x50
	CmdGetPseudoRandom       CommandType = 0x51
	CmdPutHMACKey            CommandType = 0x52
	CmdHMACData              CommandType = 0x53
	CmdGetPubKey             CommandType = 0x54
	CmdSignDataPss           CommandType = 0x55
	CmdSignDataEcdsa         CommandType = 0x56
	CmdDecryptEcdh           CommandType = 0x57
	CmdDeleteObject          CommandType = 0x58
	CmdDecryptOaep           CommandType = 0x59
	CmdGenerateHMACKey       CommandType = 0x5a
	CmdGenerateWrapKey       CommandType = 0x5b
	CmdVerifyHMAC            CommandType = 0x5c
	CmdOTPDecrypt            CommandType = 0x60
	CmdOTPAeadCreate         CommandType = 0x61
	CmdOTPAeadRandom         CommandType = 0x62
	CmdOTPAeadRewrap         CommandType = 0x63
	CmdAttestAsymmetric      CommandType = 0x64
	CmdPutOTPAeadKey         CommandType = 0x65
	CmdGenerateOTPAeadKey    CommandType = 0x66
	CmdSetLogIndex           CommandType = 0x67
	CmdWrapData              CommandType = 0x68
	CmdUnwrapData            CommandType = 0x69
	CmdSignDataEddsa         CommandType = 0x6a
	CmdSetBlink              CommandType = 0x6b
	CmdChangeAuthKey         CommandType = 0x6c

	// Errors
	ErrOK                ErrorCode = 0x00
	ErrInvalidCommand    ErrorCode = 0x01
	ErrInvalidData       ErrorCode = 0x02
	ErrInvalidSession    ErrorCode = 0x03
	ErrAuthFail          ErrorCode = 0x04
	ErrSessionFull       ErrorCode = 0x05
	ErrSessionFailed     ErrorCode = 0x06
	ErrStorageFailed     ErrorCode = 0x07
	ErrWrongLength       ErrorCode = 0x08
	ErrInvalidPermission ErrorCode = 0x09
	ErrLogFull           ErrorCode = 0x0a
	ErrObjectNotFound    ErrorCode = 0x0b
	ErrIDIllegal         ErrorCode = 0x0c
	ErrCommandUnexecuted ErrorCode = 0xff
)

const (
	// Capabilities
	GetOpaque               Capability = 0x0000000000000001
	PutOpaque               Capability = 0x0000000000000002
	PutAuthKey              Capability = 0x0000000000000004
	PutAsymmetric           Capability = 0x0000000000000008
	AsymmetricGen           Capability = 0x0000000000000010
	AsymmetricSignPkcs      Capability = 0x0000000000000020
	AsymmetricSignPss       Capability = 0x0000000000000040
	AsymmetricSignEcdsa     Capability = 0x0000000000000080
	AsymmetricSignEddsa     Capability = 0x0000000000000100
	AsymmetricDecryptPkcs   Capability = 0x0000000000000200
	AsymmetricDecryptOaep   Capability = 0x0000000000000400
	AsymmetricDecryptEcdh   Capability = 0x0000000000000800
	ExportWrapped           Capability = 0x0000000000001000
	ImportWrapped           Capability = 0x0000000000002000
	PutWrapKey              Capability = 0x0000000000004000
	GenerateWrapKey         Capability = 0x0000000000008000
	ExportUnderWrap         Capability = 0x0000000000010000
	PutOption               Capability = 0x0000000000020000
	GetOption               Capability = 0x0000000000040000
	GetRandomness           Capability = 0x0000000000080000
	PutHmacKey              Capability = 0x0000000000100000
	HmacKeyGenerate         Capability = 0x0000000000200000
	HmacData                Capability = 0x0000000000400000
	HmacVerify              Capability = 0x0000000000800000
	Audit                   Capability = 0x0000000001000000
	SshCertify              Capability = 0x0000000002000000
	GetTemplate             Capability = 0x0000000004000000
	PutTemplate             Capability = 0x0000000008000000
	Reset                   Capability = 0x0000000010000000
	OtpDecrypt              Capability = 0x0000000020000000
	OtpAeadCreate           Capability = 0x0000000040000000
	OtpAeadRandom           Capability = 0x0000000080000000
	OtpAeadRewrapFrom       Capability = 0x0000000100000000
	OtpAeadRewrapTo         Capability = 0x0000000200000000
	Attest                  Capability = 0x0000000400000000
	PutOtpAeadKey           Capability = 0x0000000800000000
	GenerateOtpAeadKey      Capability = 0x0000001000000000
	WrapData                Capability = 0x0000002000000000
	UnwrapData              Capability = 0x0000004000000000
	DeleteOpaque            Capability = 0x0000008000000000
	DeleteAuthKey           Capability = 0x0000010000000000
	DeleteAsymmetric        Capability = 0x0000020000000000
	DeleteWrapKey           Capability = 0x0000040000000000
	DeleteHmacKey           Capability = 0x0000080000000000
	DeleteTemplate          Capability = 0x0000100000000000
	DeleteOtpAeadKey        Capability = 0x0000200000000000
	ChangeAuthenticationKey Capability = 0x0000400000000000
)

const (
	// Domains
	Domain1  Domain = 0x0001
	Domain2  Domain = 0x0002
	Domain3  Domain = 0x0004
	Domain4  Domain = 0x0008
	Domain5  Domain = 0x0010
	Domain6  Domain = 0x0020
	Domain7  Domain = 0x0040
	Domain8  Domain = 0x0080
	Domain9  Domain = 0x0100
	Domain10 Domain = 0x0200
	Domain11 Domain = 0x0400
	Domain12 Domain = 0x0800
	Domain13 Domain = 0x1000
	Domain14 Domain = 0x2000
	Domain15 Domain = 0x4000
	Domain16 Domain = 0x8000

	// object types
	TypeOpaque        ObjectType = 0x01
	AuthenticationKey ObjectType = 0x02
	AsymmetricKey     ObjectType = 0x03
	WrapKey           ObjectType = 0x04
	HmacKey           ObjectType = 0x05
	Template          ObjectType = 0x06
	OtpAeadKey        ObjectType = 0x07
)
