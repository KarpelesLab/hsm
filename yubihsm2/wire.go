package yubihsm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type Command struct {
	bytes.Buffer
	CommandType CommandType
	SessionID   *uint8
	MAC         []byte
}

func (ct CommandType) New() *Command {
	return &Command{CommandType: ct}
}

func (ct CommandType) Build(data ...interface{}) (*Command, error) {
	res := ct.New()

	for _, sub := range data {
		switch v := sub.(type) {
		case uint8, uint16, uint32, uint64, int8, int16, int32, int64:
			if err := res.WriteValue(v); err != nil {
				return nil, err
			}
		case []byte:
			if _, err := res.Write(v); err != nil {
				return nil, err
			}
		case Label:
			if err := writeLabel(res, v); err != nil {
				return nil, err
			}
		case Algorithm, ObjectID, ObjectType, Domain, Capability:
			if err := res.WriteValue(v); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("yubihsm2: unsupported type %T", v)
		}
	}

	return res, nil
}

func (c *Command) WriteValue(v interface{}) error {
	return binary.Write(c, binary.BigEndian, v)
}

func (c *Command) Serialize() []byte {
	buffer := new(bytes.Buffer)

	l := c.Len()
	if c.MAC != nil {
		l += len(c.MAC)
	}
	if c.SessionID != nil {
		l += 1
	}

	binary.Write(buffer, binary.BigEndian, uint8(c.CommandType))
	binary.Write(buffer, binary.BigEndian, uint16(l))
	if c.SessionID != nil {
		binary.Write(buffer, binary.BigEndian, *c.SessionID)
	}
	buffer.Write(c.Bytes())
	buffer.Write(c.MAC)

	return buffer.Bytes()
}

type WireResponse struct {
	*bytes.Reader
	CommandType CommandType
	Payload     []byte
}

func parseResponse(data []byte, expect CommandType) (*WireResponse, error) {
	if len(data) < 3 {
		return nil, errors.New("invalid response")
	}

	transactionType := CommandType(data[0])
	payloadLength := binary.BigEndian.Uint16(data[1:3])
	payload := data[3:]
	if len(payload) != int(payloadLength) {
		return nil, errors.New("response payload length does not equal the given length")
	}

	if transactionType == ErrorResponseCode {
		if len(payload) != 1 {
			return nil, errors.New("invalid response payload length")
		}
		return nil, ErrorCode(payload[0])
	}

	transactionType = transactionType & 0x7f

	res := &WireResponse{bytes.NewReader(payload), transactionType, payload}

	if expect != 0 && transactionType != expect {
		return res, ErrInvalidResponseType
	}

	return res, nil
}

func (w *WireResponse) Expect(expect CommandType) error {
	if w.CommandType != expect {
		return ErrInvalidResponseType
	}
	return nil
}

func (w *WireResponse) ReadValue(i interface{}) error {
	return binary.Read(w, binary.BigEndian, i)
}
