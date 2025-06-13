package socks5

import "github.com/rs/zerolog"

// Logger is used to provide debug log
type Logger interface {
	Errorf(format string, arg ...interface{})
}

// Zero is a zerolog adapter implementing Logger
type Zero struct {
	zerolog.Logger
}

// NewLogger creates a new zerolog adapter
func NewLogger(l zerolog.Logger) *Zero {
	return &Zero{Logger: l}
}

// Errorf implements the Logger interface
func (z *Zero) Errorf(format string, args ...interface{}) {
	z.Logger.Error().Msgf(format, args...)
}
