package yubihsm2

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type Command struct {
	bytes.Buffer
	CommandType CommandType
	SessionID   *uint8
	MAC         []byte
}

func NewCommand(t CommandType) *Command {
	return &Command{CommandType: t}
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

func wireResponse(data []byte) (CommandType, []byte, error) {
	if len(data) < 3 {
		return ErrorResponseCode, nil, errors.New("invalid response")
	}

	transactionType := CommandType(data[0])
	payloadLength := binary.BigEndian.Uint16(data[1:2])
	payload := data[3:]
	if len(payload) != int(payloadLength) {
		return ErrorResponseCode, nil, errors.New("response payload length does not equal the given length")
	}

	if transactionType == ErrorResponseCode {
		if len(payload) != 1 {
			return ErrorResponseCode, nil, errors.New("invalid response payload length")
		}
		return ErrorResponseCode, nil, &Error{Code: ErrorCode(payload[0])}
	}

	return transactionType & 0x7f, payload, nil
}
