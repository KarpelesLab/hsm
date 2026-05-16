package idprime

import "fmt"

// buildAPDU builds a short-form ISO 7816 APDU.
//   - data == nil omits the Lc and data field.
//   - le == -1 omits the Le field; le == 0 sends Le=00 (meaning "up to
//     256" for short-form responses).
func buildAPDU(cla, ins, p1, p2 byte, data []byte, le int) []byte {
	n := 4
	if data != nil {
		n += 1 + len(data)
	}
	if le >= 0 {
		n++
	}
	out := make([]byte, 0, n)
	out = append(out, cla, ins, p1, p2)
	if data != nil {
		out = append(out, byte(len(data)))
		out = append(out, data...)
	}
	if le >= 0 {
		out = append(out, byte(le))
	}
	return out
}

// splitStatus separates the trailing SW1 SW2 from the response payload.
func splitStatus(resp []byte) (data []byte, sw uint16, err error) {
	if len(resp) < 2 {
		return nil, 0, fmt.Errorf("idprime: short response (%d bytes)", len(resp))
	}
	sw = uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
	return resp[:len(resp)-2], sw, nil
}

// TransmitChained sends an APDU and transparently handles the 61xx
// "more data available" status by issuing GET RESPONSE until the card
// signals completion. Returns the concatenated response data and the
// final SW.
func (card *Card) TransmitChained(apdu []byte) ([]byte, uint16, error) {
	resp, err := card.Transmit(apdu)
	if err != nil {
		return nil, 0, err
	}
	data, sw, err := splitStatus(resp)
	if err != nil {
		return nil, 0, err
	}
	for sw>>8 == 0x61 {
		le := int(sw & 0xff)
		if le == 0 {
			le = 256
		}
		// GET RESPONSE: 00 C0 00 00 Le
		more, err := card.Transmit([]byte{0x00, 0xC0, 0x00, 0x00, byte(le & 0xff)})
		if err != nil {
			return data, sw, err
		}
		md, msw, err := splitStatus(more)
		if err != nil {
			return data, sw, err
		}
		data = append(data, md...)
		sw = msw
	}
	return data, sw, nil
}
