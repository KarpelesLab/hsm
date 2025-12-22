package yubihsm2

import (
	"bytes"
	"testing"
)

func TestCommandNew(t *testing.T) {
	cmd := CmdEcho.New()
	if cmd.CommandType != CmdEcho {
		t.Errorf("Expected command type %v, got %v", CmdEcho, cmd.CommandType)
	}
	if cmd.Len() != 0 {
		t.Errorf("Expected empty buffer, got length %d", cmd.Len())
	}
}

func TestCommandBuild(t *testing.T) {
	tests := []struct {
		name     string
		cmdType  CommandType
		args     []interface{}
		wantErr  bool
		expected []byte
	}{
		{
			name:     "uint8 argument",
			cmdType:  CmdEcho,
			args:     []interface{}{uint8(0x42)},
			expected: []byte{0x42},
		},
		{
			name:     "uint16 argument",
			cmdType:  CmdEcho,
			args:     []interface{}{uint16(0x1234)},
			expected: []byte{0x12, 0x34},
		},
		{
			name:     "byte slice argument",
			cmdType:  CmdEcho,
			args:     []interface{}{[]byte{0x01, 0x02, 0x03}},
			expected: []byte{0x01, 0x02, 0x03},
		},
		{
			name:     "mixed arguments",
			cmdType:  CmdEcho,
			args:     []interface{}{uint8(0x01), uint16(0x0203), []byte{0x04, 0x05}},
			expected: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{
			name:    "unsupported type",
			cmdType: CmdEcho,
			args:    []interface{}{"string"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := tt.cmdType.Build(tt.args...)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !bytes.Equal(cmd.Bytes(), tt.expected) {
				t.Errorf("Build result = %v, want %v", cmd.Bytes(), tt.expected)
			}
		})
	}
}

func TestCommandSerialize(t *testing.T) {
	tests := []struct {
		name      string
		cmdType   CommandType
		data      []byte
		sessionID *uint8
		mac       []byte
		expected  []byte
	}{
		{
			name:     "simple command",
			cmdType:  CmdEcho,
			data:     []byte{0x01, 0x02, 0x03},
			expected: []byte{0x01, 0x00, 0x03, 0x01, 0x02, 0x03},
		},
		{
			name:      "command with session ID",
			cmdType:   CmdSessionMessage,
			data:      []byte{0x01, 0x02},
			sessionID: ptrUint8(0x05),
			expected:  []byte{0x05, 0x00, 0x03, 0x05, 0x01, 0x02},
		},
		{
			name:     "command with MAC",
			cmdType:  CmdEcho,
			data:     []byte{0x01},
			mac:      []byte{0xAA, 0xBB, 0xCC, 0xDD},
			expected: []byte{0x01, 0x00, 0x05, 0x01, 0xAA, 0xBB, 0xCC, 0xDD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.cmdType.New()
			cmd.Write(tt.data)
			cmd.SessionID = tt.sessionID
			cmd.MAC = tt.mac

			result := cmd.Serialize()
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("Serialize() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseResponse(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		expect      CommandType
		wantErr     bool
		wantPayload []byte
	}{
		{
			name:        "valid response",
			data:        []byte{0x81, 0x00, 0x03, 0x01, 0x02, 0x03},
			expect:      CmdEcho,
			wantPayload: []byte{0x01, 0x02, 0x03},
		},
		{
			name:    "error response",
			data:    []byte{0xff, 0x00, 0x01, byte(ErrInvalidData)},
			expect:  CmdEcho,
			wantErr: true,
		},
		{
			name:    "too short response",
			data:    []byte{0x81, 0x00},
			expect:  CmdEcho,
			wantErr: true,
		},
		{
			name:    "length mismatch",
			data:    []byte{0x81, 0x00, 0x05, 0x01, 0x02},
			expect:  CmdEcho,
			wantErr: true,
		},
		{
			name:        "wrong command type",
			data:        []byte{0x82, 0x00, 0x01, 0x01},
			expect:      CmdEcho,
			wantErr:     true,
			wantPayload: []byte{0x01},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := parseResponse(tt.data, tt.expect)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if !bytes.Equal(resp.Payload, tt.wantPayload) {
				t.Errorf("Payload = %v, want %v", resp.Payload, tt.wantPayload)
			}
		})
	}
}

func TestWireResponseReadValue(t *testing.T) {
	data := []byte{0x01, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78}
	resp, err := parseResponse(data, CmdEcho)
	if err != nil {
		t.Fatalf("parseResponse failed: %v", err)
	}

	var val16 uint16
	err = resp.ReadValue(&val16)
	if err != nil {
		t.Errorf("ReadValue uint16 failed: %v", err)
	}
	if val16 != 0x1234 {
		t.Errorf("ReadValue uint16 = %x, want %x", val16, 0x1234)
	}

	var val16_2 uint16
	err = resp.ReadValue(&val16_2)
	if err != nil {
		t.Errorf("ReadValue uint16 second failed: %v", err)
	}
	if val16_2 != 0x5678 {
		t.Errorf("ReadValue uint16 second = %x, want %x", val16_2, 0x5678)
	}
}

func ptrUint8(v uint8) *uint8 {
	return &v
}
