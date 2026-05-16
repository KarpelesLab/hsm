package idprime

import (
	"encoding/hex"
	"fmt"
)

// DefaultAID is the Gemalto/Thales IDPrime crypto-applet AID used by the
// SafeNet eToken 5110+ FIPS and IDPrime MD tokens.
var DefaultAID, _ = hex.DecodeString("A000000018800000000662")

// Default applet INS / parameter constants observed on IDPrime MD via
// SafeNet SAC 10.9 driving an eToken 5110+ FIPS. Other IDPrime variants
// may need different values; pass overrides via the Signer config.
const (
	DefaultPINRefP2 byte = 0x11 // VERIFY PIN P2 (user PIN reference)
	DefaultKeyRef   byte = 0x12 // on-card key reference for the EC key
	DefaultAlgoRef  byte = 0x54 // ECDSA-with-hash algorithm reference

	// DefaultRSAAlgoRef is the MSE SET DST algorithm reference used
	// when no override is supplied for an RSA key signing with SHA-256.
	// The IDPrime "RSA with hash + PKCS#1 v1.5" family is encoded as
	// 0x4n: 0x42 = SHA-256, 0x43 = SHA-384, 0x44 = SHA-512. Signer.Sign
	// re-selects per hash automatically; Config.AlgoRef only overrides
	// when set to a non-default value.
	DefaultRSAAlgoRef byte = 0x42

	insVerifyPIN = 0x21 // proprietary INS (NOT standard 0x20)
	insMSE       = 0x22
	insPSO       = 0x2A
	insSelect    = 0xA4
)

// SelectApplet selects the IDPrime crypto applet by AID.
func (card *Card) SelectApplet(aid []byte) error {
	cmd := buildAPDU(0x00, insSelect, 0x04, 0x00, aid, -1)
	_, sw, err := card.TransmitChained(cmd)
	if err != nil {
		return err
	}
	if sw != 0x9000 {
		return fmt.Errorf("SELECT applet: SW=%04X", sw)
	}
	return nil
}

// VerifyPIN authenticates with the user PIN. pinRef is the P2 byte
// identifying the PIN object (default 0x11). On wrong PIN, returns an
// error including remaining attempt count when the card reports it
// (SW = 63Cn).
func (card *Card) VerifyPIN(pin string, pinRef byte) error {
	cmd := buildAPDU(0x00, insVerifyPIN, 0x00, pinRef, []byte(pin), -1)
	_, sw, err := card.TransmitChained(cmd)
	if err != nil {
		return err
	}
	if sw == 0x9000 {
		return nil
	}
	if sw>>4 == 0x63C {
		return fmt.Errorf("VERIFY PIN: bad PIN, %d attempts remaining", sw&0xF)
	}
	return fmt.Errorf("VERIFY PIN: SW=%04X", sw)
}

// MSESetDST configures the security environment for a digital-signature
// operation, selecting the algorithm reference and on-card key reference.
func (card *Card) MSESetDST(algoRef, keyRef byte) error {
	data := []byte{0x80, 0x01, algoRef, 0x84, 0x01, keyRef}
	cmd := buildAPDU(0x00, insMSE, 0x41, 0xB6, data, -1)
	_, sw, err := card.TransmitChained(cmd)
	if err != nil {
		return err
	}
	if sw != 0x9000 {
		return fmt.Errorf("MSE SET DST: SW=%04X", sw)
	}
	return nil
}

// PSOSign feeds the digest to the applet and asks it to compute the
// ECDSA signature. Returns r || s concatenated raw bytes (length = 2 *
// curve byte size, e.g. 96 for P-384).
//
// Internally:
//
//	00 2A 90 A0 Lc 90 <hashLen> <hash>       -> 61 xx
//	00 C0 00 00 xx                            -> <echo> 9000
//	00 2A 9E 9A 00                            -> <r||s> 9000
func (card *Card) PSOSign(digest []byte) ([]byte, error) {
	hashed := make([]byte, 0, 2+len(digest))
	hashed = append(hashed, 0x90, byte(len(digest)))
	hashed = append(hashed, digest...)
	cmd := buildAPDU(0x00, insPSO, 0x90, 0xA0, hashed, -1)
	if _, sw, err := card.TransmitChained(cmd); err != nil {
		return nil, err
	} else if sw != 0x9000 {
		return nil, fmt.Errorf("PSO HASH: SW=%04X", sw)
	}
	// PSO compute digital signature: 00 2A 9E 9A 00 (Le=00 → up to 256).
	data, sw, err := card.TransmitChained([]byte{0x00, insPSO, 0x9E, 0x9A, 0x00})
	if err != nil {
		return nil, err
	}
	if sw != 0x9000 {
		return nil, fmt.Errorf("PSO COMPUTE: SW=%04X", sw)
	}
	return data, nil
}

// GetChallenge issues the standard ISO 7816-4 GET CHALLENGE APDU
// (00 84 00 00 Le) and returns n cryptographically random bytes from
// the card's hardware RNG. n must be 1..256; pass 256 by sending Le=00.
// Callers needing more than 256 bytes should call this in a loop.
func (card *Card) GetChallenge(n int) ([]byte, error) {
	if n < 1 || n > 256 {
		return nil, fmt.Errorf("idprime: GetChallenge n=%d out of range (1..256)", n)
	}
	le := byte(n)
	if n == 256 {
		le = 0 // short Le=00 means "up to 256"
	}
	cmd := []byte{0x00, 0x84, 0x00, 0x00, le}
	data, sw, err := card.TransmitChained(cmd)
	if err != nil {
		return nil, err
	}
	if sw != 0x9000 {
		return nil, fmt.Errorf("GET CHALLENGE: SW=%04X", sw)
	}
	if len(data) != n {
		return nil, fmt.Errorf("idprime: GET CHALLENGE returned %d bytes (want %d)", len(data), n)
	}
	return data, nil
}

// Logout deauthenticates the current PIN session. Best-effort.
func (card *Card) Logout() {
	_, _ = card.Transmit([]byte{0x00, 0x82, 0xFF, 0x00})
	_, _ = card.Transmit([]byte{0x00, insVerifyPIN, 0x00, DefaultPINRefP2})
	_, _ = card.Transmit([]byte{0x00, insVerifyPIN, 0xFF, DefaultPINRefP2})
}
