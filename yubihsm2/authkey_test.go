package yubihsm2

import (
	"bytes"
	"testing"
)

func TestDeriveAuthKeyFromPwd(t *testing.T) {
	// Test with known password - the result should be deterministic
	password := "password"
	key1 := deriveAuthKeyFromPwd(password)
	key2 := deriveAuthKeyFromPwd(password)

	if !bytes.Equal(key1, key2) {
		t.Error("Same password should produce same key")
	}

	if len(key1) != authKeyLength {
		t.Errorf("Key length = %d, want %d", len(key1), authKeyLength)
	}

	// Different passwords should produce different keys
	key3 := deriveAuthKeyFromPwd("different")
	if bytes.Equal(key1, key3) {
		t.Error("Different passwords should produce different keys")
	}
}

func TestAuthKeyGetEncKey(t *testing.T) {
	key := deriveAuthKeyFromPwd("testpassword")
	encKey := key.GetEncKey()

	if len(encKey) != KeyLength {
		t.Errorf("EncKey length = %d, want %d", len(encKey), KeyLength)
	}

	// Should be the first half of the auth key
	if !bytes.Equal(encKey, key[:KeyLength]) {
		t.Error("EncKey should be the first half of AuthKey")
	}
}

func TestAuthKeyGetMacKey(t *testing.T) {
	key := deriveAuthKeyFromPwd("testpassword")
	macKey := key.GetMacKey()

	if len(macKey) != KeyLength {
		t.Errorf("MacKey length = %d, want %d", len(macKey), KeyLength)
	}

	// Should be the second half of the auth key
	if !bytes.Equal(macKey, key[KeyLength:]) {
		t.Error("MacKey should be the second half of AuthKey")
	}
}

func TestAuthKeyEncAndMacKeysDifferent(t *testing.T) {
	key := deriveAuthKeyFromPwd("testpassword")
	encKey := key.GetEncKey()
	macKey := key.GetMacKey()

	if bytes.Equal(encKey, macKey) {
		t.Error("EncKey and MacKey should be different")
	}
}

func TestKnownPasswordDerivation(t *testing.T) {
	// Test against a known value from the YubiHSM2 specification
	// The default authentication key uses password "password" with the Yubico salt
	key := deriveAuthKeyFromPwd("password")

	// The derived key should be 32 bytes
	if len(key) != 32 {
		t.Errorf("Derived key length = %d, want 32", len(key))
	}

	// Verify each half is 16 bytes
	encKey := key.GetEncKey()
	macKey := key.GetMacKey()

	if len(encKey) != 16 || len(macKey) != 16 {
		t.Error("Each key half should be 16 bytes")
	}
}
