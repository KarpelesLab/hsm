package yubihsm2

import (
	"testing"
)

func TestAlgorithmValues(t *testing.T) {
	// Test that algorithm values match the YubiHSM2 specification
	tests := []struct {
		algo     Algorithm
		expected uint8
	}{
		{RsaPkcs1Sha1, 1},
		{RsaPkcs1Sha256, 2},
		{RsaPkcs1Sha384, 3},
		{RsaPkcs1Sha512, 4},
		{RsaPssSha1, 5},
		{RsaPssSha256, 6},
		{RsaPssSha384, 7},
		{RsaPssSha512, 8},
		{Rsa2048, 9},
		{Rsa3072, 10},
		{Rsa4096, 11},
		{Secp256r1, 12},
		{Secp384r1, 13},
		{Secp521r1, 14},
		{Secp256k1, 15},
		{Brainpool256r1, 16},
		{Brainpool384r1, 17},
		{Brainpool512r1, 18},
		{HmacSha1, 19},
		{HmacSha256, 20},
		{HmacSha384, 21},
		{HmacSha512, 22},
		{EcdsaSha1, 23},
		{Ecdh, 24},
		{RsaOaepSha1, 25},
		{RsaOaepSha256, 26},
		{RsaOaepSha384, 27},
		{RsaOaepSha512, 28},
		{Aes128CcmWrap, 29},
		{OpaqueData, 30},
		{OpaqueX509Cert, 31},
		{Mgf1Sha1, 32},
		{Mgf1Sha256, 33},
		{Mgf1Sha384, 34},
		{Mgf1Sha512, 35},
		{SshTemplate, 36},
		{YubicoOtpAes128, 37},
		{YubicoAesAuth, 38},
		{YubicoOtpAes192, 39},
		{YubicoOtpAes256, 40},
		{Aes192CcmWrap, 41},
		{Aes256CcmWrap, 42},
		{EcdsaSha256, 43},
		{EcdsaSha384, 44},
		{EcdsaSha512, 45},
		{Ed25519, 46},
		{Secp224r1, 47},
	}

	for _, tt := range tests {
		if uint8(tt.algo) != tt.expected {
			t.Errorf("Algorithm %v = %d, want %d", tt.algo, uint8(tt.algo), tt.expected)
		}
	}
}

func TestAlgorithmRSAKeyTypes(t *testing.T) {
	rsaKeyTypes := []Algorithm{Rsa2048, Rsa3072, Rsa4096}
	for _, algo := range rsaKeyTypes {
		if algo < 9 || algo > 11 {
			t.Errorf("RSA key type %v should be in range 9-11", algo)
		}
	}
}

func TestAlgorithmECDSACurves(t *testing.T) {
	ecCurves := []Algorithm{Secp256r1, Secp384r1, Secp521r1, Secp256k1}
	for _, algo := range ecCurves {
		if algo < 12 || algo > 15 {
			t.Errorf("ECDSA curve %v should be in range 12-15", algo)
		}
	}
}
