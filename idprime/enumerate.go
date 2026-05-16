package idprime

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// On-card file identifiers used by IDPrime MD's Microsoft-minidriver
// layout. Other FIDs (cardid, cardcf, container-map, ACL tables, etc.)
// are also present but not needed for enumeration.
const (
	fidCardApps uint16 = 0x0101 // directory of named files (cardapps)
)

// CardObject is one entry from the cardapps directory.
//
// On IDPrime MD the directory is an array of fixed-size 21-byte records
// laying out the on-card "file system" the Microsoft minidriver layers
// on top of ISO-7816: each record names a file by ASCII label + 8-byte
// namespace ("mscp" for minidriver, "p11" for the PKCS#11 mapper), the
// 2-byte EF identifier, and the file size.
type CardObject struct {
	Type byte
	FID  uint16
	Size uint16
	Name string // e.g. "kxc00", "msroots", "cardid"
	Ext  string // namespace: "mscp", "p11", or ""
}

// CertInfo is one certificate enumerated from the card together with
// the matching on-card private-key reference (suitable for use as
// Config.KeyRef in idprime.New).
type CertInfo struct {
	Cert      *x509.Certificate
	FID       uint16 // on-card file identifier of the kxc## file
	Container int    // numeric suffix from the kxc##/kxc## name
	KeyRef    byte   // on-card private-key reference to pass to MSE:SET DST
	AlgoRef   byte   // recommended algorithm reference for this key
}

// ListCardApps SELECTs and READs the cardapps directory and parses it.
// The card applet must already be SELECTed; this function does not.
func (card *Card) ListCardApps() ([]CardObject, error) {
	data, err := card.ReadFile(fidCardApps)
	if err != nil {
		return nil, fmt.Errorf("read cardapps: %w", err)
	}
	return parseCardApps(data), nil
}

func parseCardApps(data []byte) []CardObject {
	const entrySize = 21
	var out []CardObject
	for off := 0; off+entrySize <= len(data); off += entrySize {
		e := data[off : off+entrySize]
		fid := uint16(e[1])<<8 | uint16(e[2])
		size := uint16(e[3])<<8 | uint16(e[4])
		if fid == 0 && size == 0 && e[0] == 0 {
			continue // empty slot
		}
		name := strings.TrimRight(string(e[5:13]), "\x00")
		ext := strings.TrimRight(string(e[13:21]), "\x00")
		out = append(out, CardObject{Type: e[0], FID: fid, Size: size, Name: name, Ext: ext})
	}
	return out
}

// ReadFile selects an EF by file identifier and reads it in full. Reads
// are chunked at 0xD8 (216) bytes to fit within MAX_BUFFER_SIZE.
func (card *Card) ReadFile(fid uint16) ([]byte, error) {
	sel := []byte{0x00, insSelect, 0x00, 0x00, 0x02, byte(fid >> 8), byte(fid & 0xff), 0x00}
	fci, sw, err := card.TransmitChained(sel)
	if err != nil {
		return nil, err
	}
	if sw != 0x9000 {
		return nil, fmt.Errorf("SELECT 0x%04X: SW=%04X", fid, sw)
	}
	size := parseFileSize(fci)
	if size == 0 {
		return nil, fmt.Errorf("SELECT 0x%04X: no size in FCI", fid)
	}
	var buf bytes.Buffer
	const chunk = 0xD8
	for off := 0; off < size; {
		n := chunk
		if size-off < n {
			n = size - off
		}
		cmd := []byte{0x00, 0xB0, byte(off >> 8), byte(off & 0xff), byte(n)}
		data, sw, err := card.TransmitChained(cmd)
		if err != nil {
			return nil, err
		}
		if sw != 0x9000 {
			return nil, fmt.Errorf("READ BINARY 0x%04X@%d: SW=%04X", fid, off, sw)
		}
		if len(data) == 0 {
			break
		}
		buf.Write(data)
		off += len(data)
	}
	return buf.Bytes(), nil
}

// parseFileSize extracts the file size (tag 0x81) from an FCI template
// (outer tag 0x6F). Returns 0 if not found.
func parseFileSize(fci []byte) int {
	if len(fci) < 4 || fci[0] != 0x6F {
		return 0
	}
	inner := fci[2:]
	for i := 0; i+2 < len(inner); {
		tag := inner[i]
		l := int(inner[i+1])
		if i+2+l > len(inner) {
			return 0
		}
		v := inner[i+2 : i+2+l]
		if tag == 0x81 && l == 2 {
			return int(v[0])<<8 | int(v[1])
		}
		i += 2 + l
	}
	return 0
}

// EnumerateCerts SELECTs the IDPrime applet, walks the cardapps
// directory, decompresses every kxc## file, parses it as an X.509
// certificate, then matches each certificate to its on-card private
// key reference via GET DATA (template B6). Returns one CertInfo per
// cert whose matching private key exists on the card.
//
// No PIN is required: certs and public-key templates are readable
// without authentication.
func (card *Card) EnumerateCerts() ([]CertInfo, error) {
	if err := card.SelectApplet(DefaultAID); err != nil {
		return nil, err
	}
	apps, err := card.ListCardApps()
	if err != nil {
		return nil, err
	}
	var out []CertInfo
	for _, app := range apps {
		if app.Ext != "mscp" || !strings.HasPrefix(app.Name, "kxc") {
			continue
		}
		container, err := strconv.Atoi(strings.TrimPrefix(app.Name, "kxc"))
		if err != nil {
			continue
		}
		raw, err := card.ReadFile(app.FID)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", app.Name, err)
		}
		der, err := decompressCert(raw)
		if err != nil {
			return nil, fmt.Errorf("decompress %s: %w", app.Name, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", app.Name, err)
		}
		keyRef, err := card.findKeyRefForCert(cert)
		if err != nil {
			continue // no on-card private key matches this cert; skip
		}
		algoRef, err := card.GetKeyAlgoRef(keyRef)
		if err != nil {
			algoRef = DefaultAlgoRef
		}
		out = append(out, CertInfo{
			Cert:      cert,
			FID:       app.FID,
			Container: container,
			KeyRef:    keyRef,
			AlgoRef:   algoRef,
		})
	}
	return out, nil
}

// ErrNoMSRoots is returned by ReadMSRoots when the card does not carry
// an msroots file in its cardapps directory.
var ErrNoMSRoots = errors.New("idprime: no msroots file on card")

// ReadMSRoots reads and decompresses the on-card "msroots" file, which
// holds the Microsoft-minidriver-format CA chain as a degenerate PKCS#7
// SignedData wrapper around the issuer/root certificates. Returns
// ErrNoMSRoots when the file is not present.
//
// The applet must already be SELECTed.
func (card *Card) ReadMSRoots() ([]byte, error) {
	apps, err := card.ListCardApps()
	if err != nil {
		return nil, err
	}
	for _, app := range apps {
		if app.Ext == "mscp" && app.Name == "msroots" {
			raw, err := card.ReadFile(app.FID)
			if err != nil {
				return nil, fmt.Errorf("read msroots: %w", err)
			}
			return decompressCert(raw)
		}
	}
	return nil, ErrNoMSRoots
}

// ReadIntermediates reads msroots and returns the embedded
// intermediate/root certificates. Returns a nil slice (and no error)
// when the card has no msroots file.
//
// The applet must already be SELECTed.
func (card *Card) ReadIntermediates() ([]*x509.Certificate, error) {
	der, err := card.ReadMSRoots()
	if err != nil {
		if errors.Is(err, ErrNoMSRoots) {
			return nil, nil
		}
		return nil, err
	}
	return parsePKCS7Certificates(der)
}

// GetKeyAlgoRef queries the applet for the algorithm reference assigned
// to a given private key (GET DATA, template B6, tag DF 3B). Returns the
// single byte the card reports (e.g. 0x55 on the SafeNet eToken 5110+
// FIPS we've sniffed).
func (card *Card) GetKeyAlgoRef(keyRef byte) (byte, error) {
	cmd := []byte{
		0x00, 0xCB, 0x00, 0xFF, 0x08,
		0xB6, 0x03, 0x83, 0x01, keyRef,
		0xDF, 0x3B, 0x00,
		0x00,
	}
	data, sw, err := card.TransmitChained(cmd)
	if err != nil {
		return 0, err
	}
	if sw != 0x9000 {
		return 0, fmt.Errorf("GET DATA B6 key=%02X DF3B: SW=%04X", keyRef, sw)
	}
	val := findBERTag2(data, 0xDF, 0x3B)
	if len(val) != 1 {
		return 0, fmt.Errorf("DF3B value length %d (expected 1)", len(val))
	}
	return val[0], nil
}

// parsePKCS7Certificates extracts the certificates field from a
// degenerate PKCS#7 SignedData ContentInfo (the format used by the
// msroots file).
func parsePKCS7Certificates(der []byte) ([]*x509.Certificate, error) {
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,tag:0"`
	}
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("parse ContentInfo: %w", err)
	}
	// 1.2.840.113549.1.7.2 = signedData
	signedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	if !ci.ContentType.Equal(signedData) {
		return nil, fmt.Errorf("msroots: unexpected contentType %v", ci.ContentType)
	}
	var sd struct {
		Version          int
		DigestAlgorithms asn1.RawValue `asn1:"set"`
		EncapContentInfo asn1.RawValue
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		CRLs             asn1.RawValue `asn1:"optional,tag:1"`
		SignerInfos      asn1.RawValue `asn1:"set"`
	}
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("parse SignedData: %w", err)
	}
	if len(sd.Certificates.Bytes) == 0 {
		return nil, nil
	}
	// Certificates is [0] IMPLICIT SET OF Certificate; .Bytes is the
	// concatenated cert SEQUENCEs, which is exactly what
	// ParseCertificates wants.
	return x509.ParseCertificates(sd.Certificates.Bytes)
}

// SelectValidCert returns the first enumerated certificate whose
// validity window includes the current time. Useful when a token
// carries several leaf certs from successive renewals.
func (card *Card) SelectValidCert(now time.Time) (CertInfo, error) {
	all, err := card.EnumerateCerts()
	if err != nil {
		return CertInfo{}, err
	}
	for _, ci := range all {
		if now.Before(ci.Cert.NotBefore) || now.After(ci.Cert.NotAfter) {
			continue
		}
		return ci, nil
	}
	return CertInfo{}, errors.New("idprime: no valid (non-expired) certificate on card")
}

// decompressCert parses the Microsoft-style 4-byte prefix (version u16
// LE, uncompressed-length u16 LE) and zlib-decompresses the payload.
func decompressCert(raw []byte) ([]byte, error) {
	if len(raw) < 4 {
		return nil, errors.New("compressed cert too short")
	}
	expected := int(raw[2]) | int(raw[3])<<8
	zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
	if err != nil {
		return nil, fmt.Errorf("zlib reader: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("zlib decode: %w", err)
	}
	if expected > 0 && len(out) != expected {
		return nil, fmt.Errorf("decompressed %d bytes, expected %d", len(out), expected)
	}
	return out, nil
}

// findKeyRefForCert iterates plausible on-card key references and asks
// the applet for the matching public-key blob (via GET DATA template
// B6). The reference whose returned public key matches the cert's is
// returned.
func (card *Card) findKeyRefForCert(cert *x509.Certificate) (byte, error) {
	var pubTag byte
	switch cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		pubTag = 0x86 // EC point
	case *rsa.PublicKey:
		pubTag = 0x81 // RSA modulus
	default:
		return 0, fmt.Errorf("unsupported public key type %T", cert.PublicKey)
	}
	for ref := byte(0x10); ref <= 0x1F; ref++ {
		pk, err := card.getOnCardPubKey(ref, pubTag)
		if err != nil {
			continue
		}
		if publicKeysEqual(cert.PublicKey, pk) {
			return ref, nil
		}
	}
	return 0, errors.New("no matching on-card key reference")
}

// getOnCardPubKey fetches the public key for a specific key reference
// using the IDPrime GET DATA "key reference template" form.
func (card *Card) getOnCardPubKey(keyRef, pubTag byte) (interface{}, error) {
	cmd := []byte{
		0x00, 0xCB, 0x00, 0xFF, 0x0A,
		0xB6, 0x03, 0x83, 0x01, keyRef,
		0x7F, 0x49, 0x02, pubTag, 0x00,
		0x00,
	}
	data, sw, err := card.TransmitChained(cmd)
	if err != nil {
		return nil, err
	}
	if sw != 0x9000 {
		return nil, fmt.Errorf("GET DATA B6 key=%02X tag=%02X: SW=%04X", keyRef, pubTag, sw)
	}
	inner := findBERTag2(data, 0x7F, 0x49)
	if inner == nil {
		return nil, errors.New("7F49 not in response")
	}
	val := findBERTag1(inner, pubTag)
	if val == nil {
		return nil, fmt.Errorf("inner tag 0x%02X not in 7F49", pubTag)
	}
	switch pubTag {
	case 0x86:
		if len(val) < 1 || val[0] != 0x04 {
			return nil, errors.New("EC point not uncompressed")
		}
		coord := (len(val) - 1) / 2
		var curve elliptic.Curve
		switch coord {
		case 32:
			curve = elliptic.P256()
		case 48:
			curve = elliptic.P384()
		case 66:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unknown EC coord length %d", coord)
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(val[1 : 1+coord]),
			Y:     new(big.Int).SetBytes(val[1+coord:]),
		}, nil
	case 0x81:
		return &rsa.PublicKey{N: new(big.Int).SetBytes(val), E: 65537}, nil
	}
	return nil, errors.New("unsupported pubTag")
}

// findBERTag1 / findBERTag2 scan a BER-encoded buffer for the first
// occurrence of a single- or two-byte tag at the top level and return
// its value. Both forms support definite-length (short or long form)
// encodings; primitive tags only.
func findBERTag1(data []byte, tag byte) []byte {
	for i := 0; i < len(data); {
		t1 := data[i]
		taglen := 1
		if t1&0x1F == 0x1F {
			taglen = 2
		}
		l, ll := berReadLen(data, i+taglen)
		valStart := i + taglen + ll
		valEnd := valStart + l
		if valEnd > len(data) {
			return nil
		}
		if taglen == 1 && t1 == tag {
			return data[valStart:valEnd]
		}
		i = valEnd
	}
	return nil
}

func findBERTag2(data []byte, t1, t2 byte) []byte {
	for i := 0; i < len(data); {
		ttag1 := data[i]
		taglen := 1
		if ttag1&0x1F == 0x1F {
			taglen = 2
		}
		l, ll := berReadLen(data, i+taglen)
		valStart := i + taglen + ll
		valEnd := valStart + l
		if valEnd > len(data) {
			return nil
		}
		if taglen == 2 && ttag1 == t1 && data[i+1] == t2 {
			return data[valStart:valEnd]
		}
		i = valEnd
	}
	return nil
}

func berReadLen(data []byte, i int) (length, bytesUsed int) {
	if i >= len(data) {
		return 0, 0
	}
	l := int(data[i])
	if l&0x80 == 0 {
		return l, 1
	}
	n := l & 0x7F
	if n == 0 || i+1+n > len(data) {
		return 0, 1 + n
	}
	out := 0
	for k := 0; k < n; k++ {
		out = (out << 8) | int(data[i+1+k])
	}
	return out, 1 + n
}

func publicKeysEqual(a, b interface{}) bool {
	switch ka := a.(type) {
	case *ecdsa.PublicKey:
		kb, ok := b.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return ka.Curve == kb.Curve && ka.X.Cmp(kb.X) == 0 && ka.Y.Cmp(kb.Y) == 0
	case *rsa.PublicKey:
		kb, ok := b.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return ka.E == kb.E && ka.N.Cmp(kb.N) == 0
	}
	return false
}
