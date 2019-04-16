package yubihsm2

type Algorithm uint8

// Algorithms
// See: https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html

const (
	_                               = iota // ignore zero
	AlgorithmRsaPkcs1Sha1 Algorithm = iota
	AlgorithmRsaPkcs1Sha256
	AlgorithmRsaPkcs1Sha384
	AlgorithmRsaPkcs1Sha512
	AlgorithmRsaPssSha1
	AlgorithmRsaPssSha256
	AlgorithmRsaPssSha384
	AlgorithmRsaPssSha512
	AlgorithmRsa2048
	AlgorithmRsa3072
	AlgorithmRsa4096
	AlgorithmSecp256r1
	AlgorithmSecp384r1
	AlgorithmSecp521r1
	AlgorithmSecp256k1
	AlgorithmBrainpool256r1
	AlgorithmBrainpool384r1
	AlgorithmBrainpool512r1
	AlgorithmHmacSha1
	AlgorithmHmacSha256
	AlgorithmHmacSha384
	AlgorithmHmacSha512
	AlgorithmEcdsaSha1
	AlgorithmEcdh
	AlgorithmRsaOaepSha1
	AlgorithmRsaOaepSha256
	AlgorithmRsaOaepSha384
	AlgorithmRsaOaepSha512
	AlgorithmAes128CcmWrap
	AlgorithmOpaqueData
	AlgorithmOpaqueX509Cert
	AlgorithmMgf1Sha1
	AlgorithmMgf1Sha256
	AlgorithmMgf1Sha384
	AlgorithmMgf1Sha512
	AlgorithmSshTemplate
	AlgorithmYubicoOtpAes128
	AlgorithmYubicoAesAuth
	AlgorithmYubicoOtpAes192
	AlgorithmYubicoOtpAes256
	AlgorithmAes192CcmWrap
	AlgorithmAes256CcmWrap
	AlgorithmEcdsaSha256
	AlgorithmEcdsaSha384
	AlgorithmEcdsaSha512
	AlgorighmED25519
	AlgorithmSecp224r1
)
