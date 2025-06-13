package handler

import (
	"context"
	"io"
	"net"

	"github.com/things-go/go-socks5/statute"
)

// AddressRewriter is used to rewrite a destination transparently
// returned context and dest address.
type AddressRewriter interface {
	Rewrite(ctx context.Context, request *Request) (context.Context, *statute.AddrSpec)
}

// Request represents request received by a server
// Derived from statute.Request and adds additional fields
// like authentication context and addresses.
type Request struct {
	statute.Request
	AuthContext interface{}
	LocalAddr   net.Addr
	RemoteAddr  net.Addr
	DestAddr    *statute.AddrSpec
	Reader      io.Reader
	RawDestAddr *statute.AddrSpec
}

// ParseRequest creates a new Request from the tcp connection
func ParseRequest(bufConn io.Reader) (*Request, error) {
	hd, err := statute.ParseRequest(bufConn)
	if err != nil {
		return nil, err
	}
	return &Request{
		Request:     hd,
		RawDestAddr: &hd.DstAddr,
		Reader:      bufConn,
	}, nil
}
