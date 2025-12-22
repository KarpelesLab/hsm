package hsm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewSoftwareHSM(t *testing.T) {
	// Use a temporary directory for testing
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}
	defer hsm.Close()

	if !hsm.Ready() {
		t.Error("HSM should be ready after creation")
	}

	// Verify database file was created
	dbPath := filepath.Join(tmpDir, "hsm", "hsmdata.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file should exist")
	}
}

func TestSoftwareHSMListKeysEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}
	defer hsm.Close()

	keys, err := hsm.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("Expected 0 keys, got %d", len(keys))
	}
}

func TestSoftwareHSMListKeysByNameGeneratesKey(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}
	defer hsm.Close()

	// ListKeysByName should auto-generate a key in software mode
	keys, err := hsm.ListKeysByName("testkey")
	if err != nil {
		t.Fatalf("ListKeysByName failed: %v", err)
	}

	if len(keys) != 1 {
		t.Fatalf("Expected 1 key, got %d", len(keys))
	}

	key := keys[0]

	// Verify it's an ECDSA key
	pubKey := key.Public()
	if _, ok := pubKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("Expected ECDSA public key, got %T", pubKey)
	}

	// Verify the key can be retrieved again
	keys2, err := hsm.ListKeysByName("testkey")
	if err != nil {
		t.Fatalf("Second ListKeysByName failed: %v", err)
	}

	if len(keys2) != 1 {
		t.Fatalf("Expected 1 key on second call, got %d", len(keys2))
	}

	// Verify it's the same key (same public key)
	pubKey2 := keys2[0].Public()
	ecKey1 := pubKey.(*ecdsa.PublicKey)
	ecKey2 := pubKey2.(*ecdsa.PublicKey)

	if ecKey1.X.Cmp(ecKey2.X) != 0 || ecKey1.Y.Cmp(ecKey2.Y) != 0 {
		t.Error("Same key name should return same key")
	}
}

func TestSoftwareHSMKeySign(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}
	defer hsm.Close()

	keys, err := hsm.ListKeysByName("signkey")
	if err != nil {
		t.Fatalf("ListKeysByName failed: %v", err)
	}

	key := keys[0]

	// Sign some data
	message := []byte("test message to sign")
	hash := sha256.Sum256(message)

	sig, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if len(sig) == 0 {
		t.Error("Signature should not be empty")
	}

	// Verify the signature
	pubKey := key.Public().(*ecdsa.PublicKey)
	valid := ecdsa.VerifyASN1(pubKey, hash[:], sig)
	if !valid {
		t.Error("Signature verification failed")
	}
}

func TestSoftwareHSMKeyPublicBlob(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}
	defer hsm.Close()

	keys, err := hsm.ListKeysByName("blobkey")
	if err != nil {
		t.Fatalf("ListKeysByName failed: %v", err)
	}

	key := keys[0]

	blob, err := key.PublicBlob()
	if err != nil {
		t.Fatalf("PublicBlob failed: %v", err)
	}

	if len(blob) == 0 {
		t.Error("Public blob should not be empty")
	}

	// Verify the blob can be parsed
	pubKeyI, err := x509.ParsePKIXPublicKey(blob)
	if err != nil {
		t.Fatalf("Failed to parse public key blob: %v", err)
	}

	if _, ok := pubKeyI.(*ecdsa.PublicKey); !ok {
		t.Errorf("Expected ECDSA public key from blob, got %T", pubKeyI)
	}
}

func TestSoftwareHSMKeyString(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}
	defer hsm.Close()

	keys, err := hsm.ListKeysByName("stringkey")
	if err != nil {
		t.Fatalf("ListKeysByName failed: %v", err)
	}

	key := keys[0]
	str := key.String()

	if str == "" {
		t.Error("Key String() should not be empty")
	}
}

func TestSoftwareHSMCertificates(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}
	defer hsm.Close()

	// Get a key to sign with
	keys, err := hsm.ListKeysByName("certkey")
	if err != nil {
		t.Fatalf("ListKeysByName failed: %v", err)
	}
	key := keys[0]

	// Create a test certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	// Store the certificate
	err = hsm.PutCertificate("testcert", cert)
	if err != nil {
		t.Fatalf("PutCertificate failed: %v", err)
	}

	// Retrieve the certificate
	retrieved, err := hsm.GetCertificate("testcert")
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if retrieved.Subject.CommonName != "Test Certificate" {
		t.Errorf("Certificate CN = %q, want %q", retrieved.Subject.CommonName, "Test Certificate")
	}
}

func TestSoftwareHSMGetCertificateNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}
	defer hsm.Close()

	_, err = hsm.GetCertificate("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent certificate")
	}
	if !os.IsNotExist(err) {
		t.Errorf("Expected os.ErrNotExist, got %v", err)
	}
}

func TestSoftwareHSMPutCertificateInvalid(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}
	defer hsm.Close()

	// Try to store a certificate with nil Raw
	invalidCert := &x509.Certificate{
		Raw: nil,
	}

	err = hsm.PutCertificate("invalid", invalidCert)
	if err == nil {
		t.Error("Expected error for certificate with nil Raw")
	}
}

func TestSoftwareHSMClose(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}

	err = hsm.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Closing again should be safe
	err = hsm.Close()
	if err != nil {
		t.Errorf("Second Close should not fail: %v", err)
	}
}

func TestSoftwareHSMListKeysAfterGeneration(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}
	defer hsm.Close()

	// Generate some keys
	_, err = hsm.ListKeysByName("key1")
	if err != nil {
		t.Fatalf("ListKeysByName key1 failed: %v", err)
	}

	_, err = hsm.ListKeysByName("key2")
	if err != nil {
		t.Fatalf("ListKeysByName key2 failed: %v", err)
	}

	// List all keys
	keys, err := hsm.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}

	if len(keys) != 2 {
		t.Errorf("Expected 2 keys, got %d", len(keys))
	}
}
