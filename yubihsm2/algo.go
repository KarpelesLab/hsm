package yubihsm2

type Algorithm uint8

// Algorithms
// See: https://developers.yubico.com/YubiHSM2/Concepts/Algorithms.html

const (
	_                                  = iota // ignore zero
	AlgorithmRsaPkcs1Sha1    Algorithm = iota // 1
	AlgorithmRsaPkcs1Sha256                   // 2
	AlgorithmRsaPkcs1Sha384                   // 3
	AlgorithmRsaPkcs1Sha512                   // 4
	AlgorithmRsaPssSha1                       // 5
	AlgorithmRsaPssSha256                     // 6
	AlgorithmRsaPssSha384                     // 7
	AlgorithmRsaPssSha512                     // 8
	AlgorithmRsa2048                          // 9
	AlgorithmRsa3072                          // 10
	AlgorithmRsa4096                          // 11
	AlgorithmSecp256r1                        // 12
	AlgorithmSecp384r1                        // 13
	AlgorithmSecp521r1                        // 14
	AlgorithmSecp256k1                        // 15
	AlgorithmBrainpool256r1                   // 16
	AlgorithmBrainpool384r1                   // 17
	AlgorithmBrainpool512r1                   // 18
	AlgorithmHmacSha1                         // 19
	AlgorithmHmacSha256                       // 20
	AlgorithmHmacSha384                       // 21
	AlgorithmHmacSha512                       // 22
	AlgorithmEcdsaSha1                        // 23
	AlgorithmEcdh                             // 24
	AlgorithmRsaOaepSha1                      // 25
	AlgorithmRsaOaepSha256                    // 26
	AlgorithmRsaOaepSha384                    // 27
	AlgorithmRsaOaepSha512                    // 28
	AlgorithmAes128CcmWrap                    // 29
	AlgorithmOpaqueData                       // 30
	AlgorithmOpaqueX509Cert                   // 31
	AlgorithmMgf1Sha1                         // 32
	AlgorithmMgf1Sha256                       // 33
	AlgorithmMgf1Sha384                       // 34
	AlgorithmMgf1Sha512                       // 35
	AlgorithmSshTemplate                      // 36
	AlgorithmYubicoOtpAes128                  // 37
	AlgorithmYubicoAesAuth                    // 38
	AlgorithmYubicoOtpAes192                  // 39
	AlgorithmYubicoOtpAes256                  // 40
	AlgorithmAes192CcmWrap                    // 41
	AlgorithmAes256CcmWrap                    // 42
	AlgorithmEcdsaSha256                      // 43
	AlgorithmEcdsaSha384                      // 44
	AlgorithmEcdsaSha512                      // 45
	AlgorighmED25519                          // 46
	AlgorithmSecp224r1                        // 47
)
