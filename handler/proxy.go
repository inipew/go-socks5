package handler

import (
	"io"
)

// Proxy copies data from src to dst using provided buffer.
// It closes write side if supported.
type closeWriter interface {
	CloseWrite() error
}

func Proxy(dst io.Writer, src io.Reader, buf []byte) error {
	if len(buf) == 0 {
		buf = make([]byte, 32*1024)
	}
	_, err := io.CopyBuffer(dst, src, buf)
	if cw, ok := dst.(closeWriter); ok {
		cw.CloseWrite() //nolint:errcheck
	}
	return err
}
