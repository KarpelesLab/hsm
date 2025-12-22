package yubihsm2

import (
	"bytes"
	"testing"
)

func TestWriteLabel(t *testing.T) {
	tests := []struct {
		name        string
		label       []byte
		wantErr     bool
		expectedLen int
	}{
		{
			name:        "empty label",
			label:       []byte{},
			expectedLen: 40,
		},
		{
			name:        "short label",
			label:       []byte("test"),
			expectedLen: 40,
		},
		{
			name:        "exact length label",
			label:       bytes.Repeat([]byte{'a'}, 40),
			expectedLen: 40,
		},
		{
			name:    "too long label",
			label:   bytes.Repeat([]byte{'a'}, 41),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			err := writeLabel(buf, tt.label)

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

			if buf.Len() != tt.expectedLen {
				t.Errorf("Written length = %d, want %d", buf.Len(), tt.expectedLen)
			}

			// Verify the label content is at the start
			written := buf.Bytes()
			if !bytes.HasPrefix(written, tt.label) {
				t.Error("Written data should start with the label")
			}

			// Verify padding is zeros
			if len(tt.label) < 40 {
				padding := written[len(tt.label):]
				for i, b := range padding {
					if b != 0 {
						t.Errorf("Padding byte %d = %x, want 0", i, b)
					}
				}
			}
		})
	}
}

func TestLabelType(t *testing.T) {
	// Test that Label type works correctly with writeLabel
	label := Label("mykey")
	buf := new(bytes.Buffer)

	err := writeLabel(buf, label)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if buf.Len() != LabelLength {
		t.Errorf("Written length = %d, want %d", buf.Len(), LabelLength)
	}
}
