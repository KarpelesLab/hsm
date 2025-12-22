package yubihsm2

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestPad(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:  "empty input",
			input: []byte{},
			// SCP03 padding: adds 0x80 followed by zeros to fill block
			expected: append([]byte{0x80}, bytes.Repeat([]byte{0}, 15)...),
		},
		{
			name:  "one byte",
			input: []byte{0x01},
			// 1 byte + 0x80 + 14 zeros = 16 bytes
			expected: append([]byte{0x01, 0x80}, bytes.Repeat([]byte{0}, 14)...),
		},
		{
			name:  "15 bytes needs padding",
			input: bytes.Repeat([]byte{0xAB}, 15),
			// 15 bytes + 0x80 = 16 bytes (exactly one block)
			expected: append(bytes.Repeat([]byte{0xAB}, 15), 0x80),
		},
		{
			name:  "exactly 16 bytes - adds full padding block",
			input: bytes.Repeat([]byte{0xAB}, 16),
			// Already a full block, but pad() returns it as-is per implementation
			expected: append(bytes.Repeat([]byte{0xAB}, 16), append([]byte{0x80}, bytes.Repeat([]byte{0}, 15)...)...),
		},
		{
			name:  "17 bytes",
			input: bytes.Repeat([]byte{0xAB}, 17),
			// 17 bytes + 0x80 + 14 zeros = 32 bytes
			expected: append(bytes.Repeat([]byte{0xAB}, 17), append([]byte{0x80}, bytes.Repeat([]byte{0}, 14)...)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pad(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("pad(%v) = %v, want %v", tt.input, result, tt.expected)
			}
			// Verify result is a multiple of block size
			if len(result)%aes.BlockSize != 0 {
				t.Errorf("pad result length %d is not a multiple of %d", len(result), aes.BlockSize)
			}
		})
	}
}

func TestUnpad(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: []byte{},
		},
		{
			name:     "single 0x80 byte",
			input:    []byte{0x80},
			expected: []byte{},
		},
		{
			name:     "data followed by 0x80",
			input:    []byte{0x01, 0x02, 0x03, 0x80},
			expected: []byte{0x01, 0x02, 0x03},
		},
		{
			name:     "data followed by 0x80 and zeros",
			input:    []byte{0x01, 0x02, 0x80, 0x00, 0x00},
			expected: []byte{0x01, 0x02},
		},
		{
			name:     "no padding marker",
			input:    []byte{0x01, 0x02, 0x03},
			expected: []byte{0x01, 0x02, 0x03},
		},
		{
			name:     "ends with zero but no 0x80",
			input:    []byte{0x01, 0x02, 0x00},
			expected: []byte{0x01, 0x02, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := unpad(tt.input)
			if !bytes.Equal(result, tt.expected) {
				t.Errorf("unpad(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestPadUnpadRoundTrip(t *testing.T) {
	testCases := [][]byte{
		{},
		{0x01},
		{0x01, 0x02, 0x03},
		bytes.Repeat([]byte{0xAB}, 15),
		bytes.Repeat([]byte{0xAB}, 16),
		bytes.Repeat([]byte{0xAB}, 17),
		bytes.Repeat([]byte{0xAB}, 100),
	}

	for _, original := range testCases {
		padded := pad(original)
		unpadded := unpad(padded)
		if !bytes.Equal(original, unpadded) {
			t.Errorf("Round trip failed: original=%v, padded=%v, unpadded=%v", original, padded, unpadded)
		}
	}
}
