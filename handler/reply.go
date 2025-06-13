package handler

import (
	"io"
	"net"

	"github.com/things-go/go-socks5/statute"
)

// SendReply is used to send a reply message.
// rep: reply status defined in statute package.
func SendReply(w io.Writer, rep uint8, bindAddr net.Addr) error {
	rsp := statute.Reply{
		Version:  statute.VersionSocks5,
		Response: rep,
		BndAddr: statute.AddrSpec{
			AddrType: statute.ATYPIPv4,
			IP:       net.IPv4zero,
			Port:     0,
		},
	}

	if rsp.Response == statute.RepSuccess {
		switch addr := bindAddr.(type) {
		case *net.TCPAddr:
			if addr != nil {
				rsp.BndAddr.IP = addr.IP
				rsp.BndAddr.Port = addr.Port
			}
		case *net.UDPAddr:
			if addr != nil {
				rsp.BndAddr.IP = addr.IP
				rsp.BndAddr.Port = addr.Port
			}
		default:
			rsp.Response = statute.RepAddrTypeNotSupported
		}

		if rsp.BndAddr.IP.To4() != nil {
			rsp.BndAddr.AddrType = statute.ATYPIPv4
		} else if rsp.BndAddr.IP.To16() != nil {
			rsp.BndAddr.AddrType = statute.ATYPIPv6
		}
	}
	_, err := w.Write(rsp.Bytes())
	return err
}
