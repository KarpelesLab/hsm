// Package idprime is a pure-Go PC/SC client and a driver for the Thales /
// Gemalto IDPrime smart-card applet (used in SafeNet eToken 5110+, IDPrime
// MD, and other tokens). It talks to the local pcscd daemon over its Unix
// socket — no CGO, no closed-source PKCS#11 library.
package idprime

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// pcscd local IPC socket. pcsc-lite hard-codes this path.
const socketPath = "/run/pcscd/pcscd.comm"

// IPC protocol version the client claims to speak. Matches pcsc-lite
// 2.x/4.5 (server is backward-compatible to 4.4).
const (
	protoMajor = 4
	protoMinor = 5
)

// Command codes (pcsc_msg_commands).
const (
	cmdEstablishContext = 0x01
	cmdReleaseContext   = 0x02
	cmdConnect          = 0x04
	cmdDisconnect       = 0x06
	cmdBeginTransaction = 0x07
	cmdEndTransaction   = 0x08
	cmdTransmit         = 0x09
	cmdVersion          = 0x11
	cmdGetReadersState  = 0x12
)

// PC/SC scopes.
const (
	ScopeUser     uint32 = 0
	ScopeTerminal uint32 = 1
	ScopeSystem   uint32 = 2
)

// PC/SC share modes.
const (
	ShareExclusive uint32 = 1
	ShareShared    uint32 = 2
	ShareDirect    uint32 = 3
)

// PC/SC card protocols.
const (
	ProtoT0  uint32 = 1
	ProtoT1  uint32 = 2
	ProtoRaw uint32 = 4
	ProtoAny        = ProtoT0 | ProtoT1
)

// Disposition values for Disconnect / EndTransaction.
const (
	LeaveCard   uint32 = 0
	ResetCard   uint32 = 1
	UnpowerCard uint32 = 2
	EjectCard   uint32 = 3
)

const (
	maxReaderName     = 128 // MAX_READERNAME
	maxAtrSize        = 33  // MAX_ATR_SIZE
	maxReaders        = 16  // PCSCLITE_MAX_READERS_CONTEXTS
	readerStateBytes  = 184 // sizeof(READER_STATE) including 3 bytes padding after cardAtr
	maxBuf            = 264 // MAX_BUFFER_SIZE
	pciStructLen      = 16  // sizeof(SCARD_IO_REQUEST) on 64-bit Linux (two unsigned longs)
)

// Reader is a smart-card reader entry from pcscd's reader-state table.
type Reader struct {
	Name     string
	State    uint32
	ATR      []byte
	Protocol uint32
}

// Context is a connected session to pcscd. Not safe for concurrent use.
type Context struct {
	conn     net.Conn
	hContext uint32
}

// Connect dials pcscd, performs the version handshake, and establishes a
// context. Returns a Context that must be Closed.
func Connect() (*Context, error) {
	c, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("idprime: dial pcscd at %s: %w", socketPath, err)
	}
	ctx := &Context{conn: c}
	if err := ctx.handshake(); err != nil {
		c.Close()
		return nil, err
	}
	if err := ctx.establish(); err != nil {
		c.Close()
		return nil, err
	}
	return ctx, nil
}

// Close releases the context and closes the underlying socket.
func (c *Context) Close() error {
	if c.hContext != 0 {
		_ = c.release()
	}
	return c.conn.Close()
}

// sendHeader writes the 8-byte rxHeader{size, command}.
func (c *Context) sendHeader(cmd uint32, bodySize uint32) error {
	var h [8]byte
	binary.LittleEndian.PutUint32(h[0:4], bodySize)
	binary.LittleEndian.PutUint32(h[4:8], cmd)
	_, err := c.conn.Write(h[:])
	return err
}

func (c *Context) handshake() error {
	if err := c.sendHeader(cmdVersion, 12); err != nil {
		return err
	}
	var req [12]byte
	binary.LittleEndian.PutUint32(req[0:4], uint32(protoMajor))
	binary.LittleEndian.PutUint32(req[4:8], uint32(protoMinor))
	if _, err := c.conn.Write(req[:]); err != nil {
		return err
	}
	var resp [12]byte
	if _, err := io.ReadFull(c.conn, resp[:]); err != nil {
		return fmt.Errorf("read version response: %w", err)
	}
	if rv := binary.LittleEndian.Uint32(resp[8:12]); rv != 0 {
		return scardErrorf(rv, "CMD_VERSION")
	}
	return nil
}

func (c *Context) establish() error {
	if err := c.sendHeader(cmdEstablishContext, 12); err != nil {
		return err
	}
	var req [12]byte
	binary.LittleEndian.PutUint32(req[0:4], ScopeSystem)
	if _, err := c.conn.Write(req[:]); err != nil {
		return err
	}
	var resp [12]byte
	if _, err := io.ReadFull(c.conn, resp[:]); err != nil {
		return fmt.Errorf("read establish response: %w", err)
	}
	if rv := binary.LittleEndian.Uint32(resp[8:12]); rv != 0 {
		return scardErrorf(rv, "ESTABLISH_CONTEXT")
	}
	c.hContext = binary.LittleEndian.Uint32(resp[4:8])
	return nil
}

func (c *Context) release() error {
	if err := c.sendHeader(cmdReleaseContext, 8); err != nil {
		return err
	}
	var req [8]byte
	binary.LittleEndian.PutUint32(req[0:4], c.hContext)
	if _, err := c.conn.Write(req[:]); err != nil {
		return err
	}
	var resp [8]byte
	if _, err := io.ReadFull(c.conn, resp[:]); err != nil {
		return err
	}
	c.hContext = 0
	if rv := binary.LittleEndian.Uint32(resp[4:8]); rv != 0 {
		return scardErrorf(rv, "RELEASE_CONTEXT")
	}
	return nil
}

// ListReaders returns the currently-attached readers from pcscd's
// READER_STATE table.
func (c *Context) ListReaders() ([]Reader, error) {
	if err := c.sendHeader(cmdGetReadersState, 0); err != nil {
		return nil, err
	}
	buf := make([]byte, readerStateBytes*maxReaders)
	if _, err := io.ReadFull(c.conn, buf); err != nil {
		return nil, fmt.Errorf("read reader-state: %w", err)
	}
	var out []Reader
	for i := 0; i < maxReaders; i++ {
		off := i * readerStateBytes
		name := cstring(buf[off : off+maxReaderName])
		if name == "" {
			continue
		}
		// offsets in READER_STATE:
		//   0..127   readerName
		//   128..131 eventCounter
		//   132..135 readerState
		//   136..139 readerSharing
		//   140..172 cardAtr (33 bytes)
		//   173..175 padding
		//   176..179 cardAtrLength
		//   180..183 cardProtocol
		state := binary.LittleEndian.Uint32(buf[off+132 : off+136])
		atrLen := binary.LittleEndian.Uint32(buf[off+176 : off+180])
		if atrLen > maxAtrSize {
			atrLen = maxAtrSize
		}
		atr := make([]byte, atrLen)
		copy(atr, buf[off+140:off+140+int(atrLen)])
		proto := binary.LittleEndian.Uint32(buf[off+180 : off+184])
		out = append(out, Reader{
			Name:     name,
			State:    state,
			ATR:      atr,
			Protocol: proto,
		})
	}
	return out, nil
}

// Card represents a connected card session.
type Card struct {
	ctx            *Context
	hCard          int32
	activeProtocol uint32
}

// Connect connects to a specific reader by full name. Use ListReaders to
// discover names. share is typically ShareShared; protocol is usually
// ProtoAny (lets pcscd negotiate).
func (c *Context) Connect(reader string, share, protocol uint32) (*Card, error) {
	if err := c.sendHeader(cmdConnect, 152); err != nil {
		return nil, err
	}
	var req [152]byte
	binary.LittleEndian.PutUint32(req[0:4], c.hContext)
	copy(req[4:4+maxReaderName], []byte(reader))
	binary.LittleEndian.PutUint32(req[132:136], share)
	binary.LittleEndian.PutUint32(req[136:140], protocol)
	if _, err := c.conn.Write(req[:]); err != nil {
		return nil, err
	}
	var resp [152]byte
	if _, err := io.ReadFull(c.conn, resp[:]); err != nil {
		return nil, fmt.Errorf("read connect response: %w", err)
	}
	if rv := binary.LittleEndian.Uint32(resp[148:152]); rv != 0 {
		return nil, scardErrorf(rv, "CONNECT")
	}
	return &Card{
		ctx:            c,
		hCard:          int32(binary.LittleEndian.Uint32(resp[140:144])),
		activeProtocol: binary.LittleEndian.Uint32(resp[144:148]),
	}, nil
}

// Disconnect ends the card session.
func (card *Card) Disconnect(disposition uint32) error {
	if err := card.ctx.sendHeader(cmdDisconnect, 12); err != nil {
		return err
	}
	var req [12]byte
	binary.LittleEndian.PutUint32(req[0:4], uint32(card.hCard))
	binary.LittleEndian.PutUint32(req[4:8], disposition)
	if _, err := card.ctx.conn.Write(req[:]); err != nil {
		return err
	}
	var resp [12]byte
	if _, err := io.ReadFull(card.ctx.conn, resp[:]); err != nil {
		return err
	}
	if rv := binary.LittleEndian.Uint32(resp[8:12]); rv != 0 {
		return scardErrorf(rv, "DISCONNECT")
	}
	return nil
}

// BeginTransaction acquires exclusive access to the card.
func (card *Card) BeginTransaction() error {
	if err := card.ctx.sendHeader(cmdBeginTransaction, 8); err != nil {
		return err
	}
	var req [8]byte
	binary.LittleEndian.PutUint32(req[0:4], uint32(card.hCard))
	if _, err := card.ctx.conn.Write(req[:]); err != nil {
		return err
	}
	var resp [8]byte
	if _, err := io.ReadFull(card.ctx.conn, resp[:]); err != nil {
		return err
	}
	if rv := binary.LittleEndian.Uint32(resp[4:8]); rv != 0 {
		return scardErrorf(rv, "BEGIN_TRANSACTION")
	}
	return nil
}

// EndTransaction releases exclusive access.
func (card *Card) EndTransaction(disposition uint32) error {
	if err := card.ctx.sendHeader(cmdEndTransaction, 12); err != nil {
		return err
	}
	var req [12]byte
	binary.LittleEndian.PutUint32(req[0:4], uint32(card.hCard))
	binary.LittleEndian.PutUint32(req[4:8], disposition)
	if _, err := card.ctx.conn.Write(req[:]); err != nil {
		return err
	}
	var resp [12]byte
	if _, err := io.ReadFull(card.ctx.conn, resp[:]); err != nil {
		return err
	}
	if rv := binary.LittleEndian.Uint32(resp[8:12]); rv != 0 {
		return scardErrorf(rv, "END_TRANSACTION")
	}
	return nil
}

// Transmit sends one APDU to the card and returns the raw response
// (including the trailing SW1 SW2). Chained responses (61xx) are NOT
// handled here; use TransmitChained for that.
func (card *Card) Transmit(apdu []byte) ([]byte, error) {
	if len(apdu) > maxBuf {
		return nil, fmt.Errorf("idprime: APDU too large (%d > %d)", len(apdu), maxBuf)
	}
	// pcscd validates header.size == sizeof(transmit_struct); the send
	// buffer is written separately, so the header announces only 32.
	if err := card.ctx.sendHeader(cmdTransmit, 32); err != nil {
		return nil, err
	}
	var ts [32]byte
	binary.LittleEndian.PutUint32(ts[0:4], uint32(card.hCard))
	binary.LittleEndian.PutUint32(ts[4:8], card.activeProtocol)  // ioSendPciProtocol
	binary.LittleEndian.PutUint32(ts[8:12], pciStructLen)        // ioSendPciLength
	binary.LittleEndian.PutUint32(ts[12:16], uint32(len(apdu)))  // cbSendLength
	binary.LittleEndian.PutUint32(ts[16:20], card.activeProtocol) // ioRecvPciProtocol
	binary.LittleEndian.PutUint32(ts[20:24], pciStructLen)       // ioRecvPciLength
	binary.LittleEndian.PutUint32(ts[24:28], maxBuf)             // pcbRecvLength (max)
	if _, err := card.ctx.conn.Write(ts[:]); err != nil {
		return nil, err
	}
	if _, err := card.ctx.conn.Write(apdu); err != nil {
		return nil, err
	}
	var resp [32]byte
	if _, err := io.ReadFull(card.ctx.conn, resp[:]); err != nil {
		return nil, fmt.Errorf("read transmit response header: %w", err)
	}
	if rv := binary.LittleEndian.Uint32(resp[28:32]); rv != 0 {
		return nil, scardErrorf(rv, "TRANSMIT")
	}
	recvLen := binary.LittleEndian.Uint32(resp[24:28])
	if recvLen > maxBuf {
		return nil, fmt.Errorf("idprime: pcscd returned %d bytes (>%d)", recvLen, maxBuf)
	}
	out := make([]byte, recvLen)
	if recvLen > 0 {
		if _, err := io.ReadFull(card.ctx.conn, out); err != nil {
			return nil, fmt.Errorf("read transmit payload: %w", err)
		}
	}
	return out, nil
}

// FindReader returns the first reader whose name contains the given
// substring (case-insensitive). If substr is empty, returns the first
// available reader.
func (c *Context) FindReader(substr string) (string, error) {
	readers, err := c.ListReaders()
	if err != nil {
		return "", err
	}
	if len(readers) == 0 {
		return "", errors.New("idprime: no readers connected")
	}
	if substr == "" {
		return readers[0].Name, nil
	}
	lower := strings.ToLower(substr)
	for _, r := range readers {
		if strings.Contains(strings.ToLower(r.Name), lower) {
			return r.Name, nil
		}
	}
	names := make([]string, 0, len(readers))
	for _, r := range readers {
		names = append(names, r.Name)
	}
	return "", fmt.Errorf("idprime: no reader matching %q (have: %s)", substr, strings.Join(names, ", "))
}

func cstring(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func scardErrorf(rv uint32, op string) error {
	return fmt.Errorf("idprime: %s: PC/SC error 0x%08X", op, rv)
}
