// Code generated by "stringer -type=Capability,ErrorCode,CommandType,ObjectType,Domain -output types_s.go"; DO NOT EDIT.

package yubihsm2

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[GetOpaque-1]
	_ = x[PutOpaque-2]
	_ = x[PutAuthKey-4]
	_ = x[PutAsymmetric-8]
	_ = x[AsymmetricGen-16]
	_ = x[AsymmetricSignPkcs-32]
	_ = x[AsymmetricSignPss-64]
	_ = x[AsymmetricSignEcdsa-128]
	_ = x[AsymmetricSignEddsa-256]
	_ = x[AsymmetricDecryptPkcs-512]
	_ = x[AsymmetricDecryptOaep-1024]
	_ = x[AsymmetricDecryptEcdh-2048]
	_ = x[ExportWrapped-4096]
	_ = x[ImportWrapped-8192]
	_ = x[PutWrapKey-16384]
	_ = x[GenerateWrapKey-32768]
	_ = x[ExportUnderWrap-65536]
	_ = x[PutOption-131072]
	_ = x[GetOption-262144]
	_ = x[GetRandomness-524288]
	_ = x[PutHmacKey-1048576]
	_ = x[HmacKeyGenerate-2097152]
	_ = x[HmacData-4194304]
	_ = x[HmacVerify-8388608]
	_ = x[Audit-16777216]
	_ = x[SshCertify-33554432]
	_ = x[GetTemplate-67108864]
	_ = x[PutTemplate-134217728]
	_ = x[Reset-268435456]
	_ = x[OtpDecrypt-536870912]
	_ = x[OtpAeadCreate-1073741824]
	_ = x[OtpAeadRandom-2147483648]
	_ = x[OtpAeadRewrapFrom-4294967296]
	_ = x[OtpAeadRewrapTo-8589934592]
	_ = x[Attest-17179869184]
	_ = x[PutOtpAeadKey-34359738368]
	_ = x[GenerateOtpAeadKey-68719476736]
	_ = x[WrapData-137438953472]
	_ = x[UnwrapData-274877906944]
	_ = x[DeleteOpaque-549755813888]
	_ = x[DeleteAuthKey-1099511627776]
	_ = x[DeleteAsymmetric-2199023255552]
	_ = x[DeleteWrapKey-4398046511104]
	_ = x[DeleteHmacKey-8796093022208]
	_ = x[DeleteTemplate-17592186044416]
	_ = x[DeleteOtpAeadKey-35184372088832]
	_ = x[ChangeAuthenticationKey-70368744177664]
}

const _Capability_name = "GetOpaquePutOpaquePutAuthKeyPutAsymmetricAsymmetricGenAsymmetricSignPkcsAsymmetricSignPssAsymmetricSignEcdsaAsymmetricSignEddsaAsymmetricDecryptPkcsAsymmetricDecryptOaepAsymmetricDecryptEcdhExportWrappedImportWrappedPutWrapKeyGenerateWrapKeyExportUnderWrapPutOptionGetOptionGetRandomnessPutHmacKeyHmacKeyGenerateHmacDataHmacVerifyAuditSshCertifyGetTemplatePutTemplateResetOtpDecryptOtpAeadCreateOtpAeadRandomOtpAeadRewrapFromOtpAeadRewrapToAttestPutOtpAeadKeyGenerateOtpAeadKeyWrapDataUnwrapDataDeleteOpaqueDeleteAuthKeyDeleteAsymmetricDeleteWrapKeyDeleteHmacKeyDeleteTemplateDeleteOtpAeadKeyChangeAuthenticationKey"

var _Capability_map = map[Capability]string{
	1:              _Capability_name[0:9],
	2:              _Capability_name[9:18],
	4:              _Capability_name[18:28],
	8:              _Capability_name[28:41],
	16:             _Capability_name[41:54],
	32:             _Capability_name[54:72],
	64:             _Capability_name[72:89],
	128:            _Capability_name[89:108],
	256:            _Capability_name[108:127],
	512:            _Capability_name[127:148],
	1024:           _Capability_name[148:169],
	2048:           _Capability_name[169:190],
	4096:           _Capability_name[190:203],
	8192:           _Capability_name[203:216],
	16384:          _Capability_name[216:226],
	32768:          _Capability_name[226:241],
	65536:          _Capability_name[241:256],
	131072:         _Capability_name[256:265],
	262144:         _Capability_name[265:274],
	524288:         _Capability_name[274:287],
	1048576:        _Capability_name[287:297],
	2097152:        _Capability_name[297:312],
	4194304:        _Capability_name[312:320],
	8388608:        _Capability_name[320:330],
	16777216:       _Capability_name[330:335],
	33554432:       _Capability_name[335:345],
	67108864:       _Capability_name[345:356],
	134217728:      _Capability_name[356:367],
	268435456:      _Capability_name[367:372],
	536870912:      _Capability_name[372:382],
	1073741824:     _Capability_name[382:395],
	2147483648:     _Capability_name[395:408],
	4294967296:     _Capability_name[408:425],
	8589934592:     _Capability_name[425:440],
	17179869184:    _Capability_name[440:446],
	34359738368:    _Capability_name[446:459],
	68719476736:    _Capability_name[459:477],
	137438953472:   _Capability_name[477:485],
	274877906944:   _Capability_name[485:495],
	549755813888:   _Capability_name[495:507],
	1099511627776:  _Capability_name[507:520],
	2199023255552:  _Capability_name[520:536],
	4398046511104:  _Capability_name[536:549],
	8796093022208:  _Capability_name[549:562],
	17592186044416: _Capability_name[562:576],
	35184372088832: _Capability_name[576:592],
	70368744177664: _Capability_name[592:615],
}

func (i Capability) String() string {
	if str, ok := _Capability_map[i]; ok {
		return str
	}
	return "Capability(" + strconv.FormatInt(int64(i), 10) + ")"
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[ErrOK-0]
	_ = x[ErrInvalidCommand-1]
	_ = x[ErrInvalidData-2]
	_ = x[ErrInvalidSession-3]
	_ = x[ErrAuthFail-4]
	_ = x[ErrSessionFull-5]
	_ = x[ErrSessionFailed-6]
	_ = x[ErrStorageFailed-7]
	_ = x[ErrWrongLength-8]
	_ = x[ErrInvalidPermission-9]
	_ = x[ErrLogFull-10]
	_ = x[ErrObjectNotFound-11]
	_ = x[ErrIDIllegal-12]
	_ = x[ErrCommandUnexecuted-255]
}

const (
	_ErrorCode_name_0 = "ErrOKErrInvalidCommandErrInvalidDataErrInvalidSessionErrAuthFailErrSessionFullErrSessionFailedErrStorageFailedErrWrongLengthErrInvalidPermissionErrLogFullErrObjectNotFoundErrIDIllegal"
	_ErrorCode_name_1 = "ErrCommandUnexecuted"
)

var (
	_ErrorCode_index_0 = [...]uint8{0, 5, 22, 36, 53, 64, 78, 94, 110, 124, 144, 154, 171, 183}
)

func (i ErrorCode) String() string {
	switch {
	case 0 <= i && i <= 12:
		return _ErrorCode_name_0[_ErrorCode_index_0[i]:_ErrorCode_index_0[i+1]]
	case i == 255:
		return _ErrorCode_name_1
	default:
		return "ErrorCode(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[CmdEcho-1]
	_ = x[CmdCreateSession-3]
	_ = x[CmdAuthenticateSession-4]
	_ = x[CmdSessionMessage-5]
	_ = x[CmdDeviceInfo-6]
	_ = x[CmdReset-8]
	_ = x[CmdCloseSession-64]
	_ = x[CmdStorageStatus-65]
	_ = x[CmdPutOpaque-66]
	_ = x[CmdGetOpaque-67]
	_ = x[CmdPutAuthKey-68]
	_ = x[CmdPutAsymmetric-69]
	_ = x[CmdGenerateAsymmetricKey-70]
	_ = x[CmdSignDataPkcs1-71]
	_ = x[CmdListObjects-72]
	_ = x[CmdDecryptPkcs1-73]
	_ = x[CmdExportWrapped-74]
	_ = x[CmdImportWrapped-75]
	_ = x[CmdPutWrapKey-76]
	_ = x[CmdGetLogs-77]
	_ = x[CmdGetObjectInfo-78]
	_ = x[CmdPutOption-79]
	_ = x[CmdGetOption-80]
	_ = x[CmdGetPseudoRandom-81]
	_ = x[CmdPutHMACKey-82]
	_ = x[CmdHMACData-83]
	_ = x[CmdGetPubKey-84]
	_ = x[CmdSignDataPss-85]
	_ = x[CmdSignDataEcdsa-86]
	_ = x[CmdDecryptEcdh-87]
	_ = x[CmdDeleteObject-88]
	_ = x[CmdDecryptOaep-89]
	_ = x[CmdGenerateHMACKey-90]
	_ = x[CmdGenerateWrapKey-91]
	_ = x[CmdVerifyHMAC-92]
	_ = x[CmdOTPDecrypt-96]
	_ = x[CmdOTPAeadCreate-97]
	_ = x[CmdOTPAeadRandom-98]
	_ = x[CmdOTPAeadRewrap-99]
	_ = x[CmdAttestAsymmetric-100]
	_ = x[CmdPutOTPAeadKey-101]
	_ = x[CmdGenerateOTPAeadKey-102]
	_ = x[CmdSetLogIndex-103]
	_ = x[CmdWrapData-104]
	_ = x[CmdUnwrapData-105]
	_ = x[CmdSignDataEddsa-106]
	_ = x[CmdSetBlink-107]
	_ = x[CmdChangeAuthKey-108]
}

const (
	_CommandType_name_0 = "CmdEcho"
	_CommandType_name_1 = "CmdCreateSessionCmdAuthenticateSessionCmdSessionMessageCmdDeviceInfo"
	_CommandType_name_2 = "CmdReset"
	_CommandType_name_3 = "CmdCloseSessionCmdStorageStatusCmdPutOpaqueCmdGetOpaqueCmdPutAuthKeyCmdPutAsymmetricCmdGenerateAsymmetricKeyCmdSignDataPkcs1CmdListObjectsCmdDecryptPkcs1CmdExportWrappedCmdImportWrappedCmdPutWrapKeyCmdGetLogsCmdGetObjectInfoCmdPutOptionCmdGetOptionCmdGetPseudoRandomCmdPutHMACKeyCmdHMACDataCmdGetPubKeyCmdSignDataPssCmdSignDataEcdsaCmdDecryptEcdhCmdDeleteObjectCmdDecryptOaepCmdGenerateHMACKeyCmdGenerateWrapKeyCmdVerifyHMAC"
	_CommandType_name_4 = "CmdOTPDecryptCmdOTPAeadCreateCmdOTPAeadRandomCmdOTPAeadRewrapCmdAttestAsymmetricCmdPutOTPAeadKeyCmdGenerateOTPAeadKeyCmdSetLogIndexCmdWrapDataCmdUnwrapDataCmdSignDataEddsaCmdSetBlinkCmdChangeAuthKey"
)

var (
	_CommandType_index_1 = [...]uint8{0, 16, 38, 55, 68}
	_CommandType_index_3 = [...]uint16{0, 15, 31, 43, 55, 68, 84, 108, 124, 138, 153, 169, 185, 198, 208, 224, 236, 248, 266, 279, 290, 302, 316, 332, 346, 361, 375, 393, 411, 424}
	_CommandType_index_4 = [...]uint8{0, 13, 29, 45, 61, 80, 96, 117, 131, 142, 155, 171, 182, 198}
)

func (i CommandType) String() string {
	switch {
	case i == 1:
		return _CommandType_name_0
	case 3 <= i && i <= 6:
		i -= 3
		return _CommandType_name_1[_CommandType_index_1[i]:_CommandType_index_1[i+1]]
	case i == 8:
		return _CommandType_name_2
	case 64 <= i && i <= 92:
		i -= 64
		return _CommandType_name_3[_CommandType_index_3[i]:_CommandType_index_3[i+1]]
	case 96 <= i && i <= 108:
		i -= 96
		return _CommandType_name_4[_CommandType_index_4[i]:_CommandType_index_4[i+1]]
	default:
		return "CommandType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[TypeOpaque-1]
	_ = x[AuthenticationKey-2]
	_ = x[AsymmetricKey-3]
	_ = x[WrapKey-4]
	_ = x[HmacKey-5]
	_ = x[Template-6]
	_ = x[OtpAeadKey-7]
}

const _ObjectType_name = "TypeOpaqueAuthenticationKeyAsymmetricKeyWrapKeyHmacKeyTemplateOtpAeadKey"

var _ObjectType_index = [...]uint8{0, 10, 27, 40, 47, 54, 62, 72}

func (i ObjectType) String() string {
	i -= 1
	if i >= ObjectType(len(_ObjectType_index)-1) {
		return "ObjectType(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _ObjectType_name[_ObjectType_index[i]:_ObjectType_index[i+1]]
}
func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[Domain1-1]
	_ = x[Domain2-2]
	_ = x[Domain3-4]
	_ = x[Domain4-8]
	_ = x[Domain5-16]
	_ = x[Domain6-32]
	_ = x[Domain7-64]
	_ = x[Domain8-128]
	_ = x[Domain9-256]
	_ = x[Domain10-512]
	_ = x[Domain11-1024]
	_ = x[Domain12-2048]
	_ = x[Domain13-4096]
	_ = x[Domain14-8192]
	_ = x[Domain15-16384]
	_ = x[Domain16-32768]
}

const _Domain_name = "Domain1Domain2Domain3Domain4Domain5Domain6Domain7Domain8Domain9Domain10Domain11Domain12Domain13Domain14Domain15Domain16"

var _Domain_map = map[Domain]string{
	1:     _Domain_name[0:7],
	2:     _Domain_name[7:14],
	4:     _Domain_name[14:21],
	8:     _Domain_name[21:28],
	16:    _Domain_name[28:35],
	32:    _Domain_name[35:42],
	64:    _Domain_name[42:49],
	128:   _Domain_name[49:56],
	256:   _Domain_name[56:63],
	512:   _Domain_name[63:71],
	1024:  _Domain_name[71:79],
	2048:  _Domain_name[79:87],
	4096:  _Domain_name[87:95],
	8192:  _Domain_name[95:103],
	16384: _Domain_name[103:111],
	32768: _Domain_name[111:119],
}

func (i Domain) String() string {
	if str, ok := _Domain_map[i]; ok {
		return str
	}
	return "Domain(" + strconv.FormatInt(int64(i), 10) + ")"
}