package yubihsm2

import (
	"errors"
	"io"
)

func writeLabel(w io.Writer, l []byte) error {
	if len(l) > 40 {
		return errors.New("yubihsm2: label too long")
	}

	_, err := w.Write(l)
	if err != nil {
		return err
	}
	if len(l) < 40 {
		buf := make([]byte, 40-len(l))
		_, err = w.Write(buf)
		if err != nil {
			return err
		}
	}
	return nil
}
