package yubihsm2

type Algorithm uint8

// Algorithms
// See: https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html

//go:generate stringer -type=Algorithm -output algo_s.go

const (
	_                         = iota // ignore zero
	RsaPkcs1Sha1    Algorithm = iota // 1
	RsaPkcs1Sha256                   // 2
	RsaPkcs1Sha384                   // 3
	RsaPkcs1Sha512                   // 4
	RsaPssSha1                       // 5
	RsaPssSha256                     // 6
	RsaPssSha384                     // 7
	RsaPssSha512                     // 8
	Rsa2048                          // 9
	Rsa3072                          // 10
	Rsa4096                          // 11
	Secp256r1                        // 12
	Secp384r1                        // 13
	Secp521r1                        // 14
	Secp256k1                        // 15
	Brainpool256r1                   // 16
	Brainpool384r1                   // 17
	Brainpool512r1                   // 18
	HmacSha1                         // 19
	HmacSha256                       // 20
	HmacSha384                       // 21
	HmacSha512                       // 22
	EcdsaSha1                        // 23
	Ecdh                             // 24
	RsaOaepSha1                      // 25
	RsaOaepSha256                    // 26
	RsaOaepSha384                    // 27
	RsaOaepSha512                    // 28
	Aes128CcmWrap                    // 29
	OpaqueData                       // 30
	OpaqueX509Cert                   // 31
	Mgf1Sha1                         // 32
	Mgf1Sha256                       // 33
	Mgf1Sha384                       // 34
	Mgf1Sha512                       // 35
	SshTemplate                      // 36
	YubicoOtpAes128                  // 37
	YubicoAesAuth                    // 38
	YubicoOtpAes192                  // 39
	YubicoOtpAes256                  // 40
	Aes192CcmWrap                    // 41
	Aes256CcmWrap                    // 42
	EcdsaSha256                      // 43
	EcdsaSha384                      // 44
	EcdsaSha512                      // 45
	Ed25519                          // 46
	Secp224r1                        // 47
)
