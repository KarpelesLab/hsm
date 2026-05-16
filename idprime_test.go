package hsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"os"
	"testing"
)

// TestIDPrimeSignLive exercises the native pure-Go pcsc-lite + IDPrime
// path against a physical token.
//
// It is skipped unless the environment is configured for a token test:
//
//	HSM=idprime
//	IDPRIME_PIN=...           (or interactive prompt)
//	IDPRIME_CERT=/path/to.pem (ECDSA leaf matching the on-card key)
//
// Verifies the returned signature against the public key in the cert,
// so the test passes only if the token actually signed correctly.
func TestIDPrimeSignLive(t *testing.T) {
	if os.Getenv("HSM") != "idprime" {
		t.Skip("set HSM=idprime to run the live IDPrime test")
	}
	h, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	keys, err := h.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("no keys returned")
	}
	k := keys[0]
	t.Logf("key: %s", k.String())

	msg := []byte("idprime live test " + os.Getenv("USER"))
	digest := sha512.Sum384(msg)

	sig, err := k.Sign(rand.Reader, digest[:], crypto.SHA384)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	t.Logf("signature: %d bytes", len(sig))

	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", k.Public())
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature failed verification against public key")
	}
	t.Log("signature verified OK against on-card public key")
}
