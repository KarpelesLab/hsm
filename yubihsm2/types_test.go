package yubihsm2

import (
	"testing"
)

func TestObjectTypes(t *testing.T) {
	// Verify object type constants match expected values
	tests := []struct {
		objType  ObjectType
		expected uint8
	}{
		{TypeOpaque, 0x01},
		{AuthenticationKey, 0x02},
		{AsymmetricKey, 0x03},
		{WrapKey, 0x04},
		{HmacKey, 0x05},
		{Template, 0x06},
		{OtpAeadKey, 0x07},
	}

	for _, tt := range tests {
		if uint8(tt.objType) != tt.expected {
			t.Errorf("ObjectType %v = %x, want %x", tt.objType, uint8(tt.objType), tt.expected)
		}
	}
}

func TestDomains(t *testing.T) {
	// Verify domain constants are powers of 2
	domains := []Domain{
		Domain1, Domain2, Domain3, Domain4,
		Domain5, Domain6, Domain7, Domain8,
		Domain9, Domain10, Domain11, Domain12,
		Domain13, Domain14, Domain15, Domain16,
	}

	for i, d := range domains {
		expected := Domain(1 << i)
		if d != expected {
			t.Errorf("Domain%d = %x, want %x", i+1, d, expected)
		}
	}
}

func TestCapabilities(t *testing.T) {
	// Test that capabilities are unique bit flags
	caps := []Capability{
		GetOpaque, PutOpaque, PutAuthKey, PutAsymmetric,
		AsymmetricGen, AsymmetricSignPkcs, AsymmetricSignPss, AsymmetricSignEcdsa,
	}

	seen := make(map[Capability]bool)
	for _, c := range caps {
		if seen[c] {
			t.Errorf("Duplicate capability value: %x", c)
		}
		seen[c] = true

		// Verify it's a single bit or combination
		if c == 0 {
			t.Errorf("Capability should not be zero")
		}
	}
}

func TestCommandTypes(t *testing.T) {
	// Verify some key command types
	tests := []struct {
		cmd      CommandType
		expected uint8
	}{
		{CmdEcho, 0x01},
		{CmdCreateSession, 0x03},
		{CmdAuthenticateSession, 0x04},
		{CmdSessionMessage, 0x05},
		{CmdDeviceInfo, 0x06},
		{CmdReset, 0x08},
		{CmdCloseSession, 0x40},
	}

	for _, tt := range tests {
		if uint8(tt.cmd) != tt.expected {
			t.Errorf("CommandType %v = %x, want %x", tt.cmd, uint8(tt.cmd), tt.expected)
		}
	}
}

func TestResponseCommandOffset(t *testing.T) {
	if ResponseCommandOffset != 0x80 {
		t.Errorf("ResponseCommandOffset = %x, want 0x80", ResponseCommandOffset)
	}
}

func TestErrorResponseCode(t *testing.T) {
	if ErrorResponseCode != 0xff {
		t.Errorf("ErrorResponseCode = %x, want 0xff", ErrorResponseCode)
	}
}

func TestLabelLength(t *testing.T) {
	if LabelLength != 40 {
		t.Errorf("LabelLength = %d, want 40", LabelLength)
	}
}
