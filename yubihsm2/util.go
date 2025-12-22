package yubihsm2

import (
	"bytes"
	"crypto/aes"
)

// pad adds a padding to src until using the mechanism specified in SCP03 until it has a len that is a multiple of
// aes.BlockSize and returns the result
func pad(src []byte) []byte {
	if aes.BlockSize-len(src)%aes.BlockSize == 0 {
		return src
	}

	padding := aes.BlockSize - len(src)%aes.BlockSize - 1
	padtext := bytes.Repeat([]byte{0}, padding)
	padtext = append([]byte{0x80}, padtext...)
	return append(src, padtext...)
}

// unpad removes the padding from src using the mechanism specified in SCP03 and returns the result
func unpad(src []byte) []byte {
	if len(src) == 0 {
		return src
	}

	lastByte := src[len(src)-1]
	if lastByte != 0x00 && lastByte != 0x80 {
		return src
	}

	padLen := 0
	for i := len(src) - 1; i >= 0; i-- {
		if src[i] == 0x00 {
			padLen++
			continue
		}
		if src[i] == 0x80 {
			padLen++
			break
		}
		// Found a non-padding byte before 0x80 marker - invalid padding, return as-is
		return src
	}

	// If we scanned the entire slice without finding 0x80, return original
	if padLen == len(src) && src[0] != 0x80 {
		return src
	}

	return src[:len(src)-padLen]
}
