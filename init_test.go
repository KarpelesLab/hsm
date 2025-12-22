package hsm

import (
	"os"
	"testing"
)

func TestNewWithSoftwareHSM(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	origHSM := os.Getenv("HSM")

	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	os.Setenv("HSM", "software")

	defer func() {
		os.Setenv("XDG_CONFIG_HOME", origConfigDir)
		os.Setenv("HSM", origHSM)
	}()

	hsm, err := New()
	if err != nil {
		t.Fatalf("New() with HSM=software failed: %v", err)
	}

	if hsm == nil {
		t.Fatal("New() returned nil HSM")
	}

	if !hsm.Ready() {
		t.Error("HSM should be ready")
	}

	// Clean up
	if sh, ok := hsm.(*SoftwareHSM); ok {
		sh.Close()
	}
}

func TestNewWithNoHSMEnv(t *testing.T) {
	origHSM := os.Getenv("HSM")
	os.Unsetenv("HSM")
	defer os.Setenv("HSM", origHSM)

	_, err := New()
	if err == nil {
		t.Error("New() without HSM env should return error")
	}
}

func TestNewWithUnknownHSM(t *testing.T) {
	origHSM := os.Getenv("HSM")
	os.Setenv("HSM", "unknown_hsm_type")
	defer os.Setenv("HSM", origHSM)

	_, err := New()
	if err == nil {
		t.Error("New() with unknown HSM type should return error")
	}
}

func TestHSMInterfaceCompliance(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}
	defer hsm.Close()

	// Verify SoftwareHSM implements HSM interface
	var _ HSM = hsm
}

func TestKeyInterfaceCompliance(t *testing.T) {
	tmpDir := t.TempDir()
	origConfigDir := os.Getenv("XDG_CONFIG_HOME")
	os.Setenv("XDG_CONFIG_HOME", tmpDir)
	defer os.Setenv("XDG_CONFIG_HOME", origConfigDir)

	hsm, err := NewSoftwareHSM()
	if err != nil {
		t.Fatalf("NewSoftwareHSM failed: %v", err)
	}
	defer hsm.Close()

	keys, err := hsm.ListKeysByName("testkey")
	if err != nil {
		t.Fatalf("ListKeysByName failed: %v", err)
	}

	if len(keys) == 0 {
		t.Fatal("Expected at least one key")
	}

	// Verify key implements Key interface
	var _ Key = keys[0]
}
