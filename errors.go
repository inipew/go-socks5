package socks5

import "errors"

var (
	ErrSendReply          = errors.New("send reply failed")
	ErrResolveDestination = errors.New("resolve destination failed")
	ErrBindBlocked        = errors.New("bind blocked by rules")
	ErrUnsupportedCommand = errors.New("unsupported command")
	ErrConnectFailed      = errors.New("connect failed")
	ErrListenUDPFailed    = errors.New("listen UDP failed")
	ErrAuthFailed         = errors.New("authentication failed")
	ErrReadDestination    = errors.New("read destination failed")
)
