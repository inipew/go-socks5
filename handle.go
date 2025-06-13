package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/things-go/go-socks5/handler"
	"github.com/things-go/go-socks5/statute"
)

// handleRequest is used for request processing after authentication
func (sf *Server) handleRequest(write io.Writer, req *handler.Request) error {
	var err error

	ctx := context.Background()
	// Resolve the address if we have a FQDN
	dest := req.RawDestAddr
	if dest.FQDN != "" {
		ctx, dest.IP, err = sf.resolver.Resolve(ctx, dest.FQDN)
		if err != nil {
			if err := handler.SendReply(write, statute.RepHostUnreachable, nil); err != nil {
				return fmt.Errorf("%w: %w", ErrSendReply, err)
			}
			return fmt.Errorf("%w [%v]: %w", ErrResolveDestination, dest.FQDN, err)
		}
	}

	// Apply any address rewrites
	req.DestAddr = req.RawDestAddr
	if sf.rewriter != nil {
		ctx, req.DestAddr = sf.rewriter.Rewrite(ctx, req)
	}

	// Check if this is allowed
	var ok bool
	ctx, ok = sf.rules.Allow(ctx, req)
	if !ok {
		if err := handler.SendReply(write, statute.RepRuleFailure, nil); err != nil {
			return fmt.Errorf("%w: %w", ErrSendReply, err)
		}
		return fmt.Errorf("%w: %v", ErrBindBlocked, req.RawDestAddr)
	}

	var last Handler
	// Switch on the command
	switch req.Command {
	case statute.CommandConnect:
		last = sf.handleConnect
		if sf.userConnectHandle != nil {
			last = sf.userConnectHandle
		}
		if len(sf.userConnectMiddlewares) != 0 {
			return sf.userConnectMiddlewares.Execute(ctx, write, req, last)
		}
	case statute.CommandBind:
		last = sf.handleBind
		if sf.userBindHandle != nil {
			last = sf.userBindHandle
		}
		if len(sf.userBindMiddlewares) != 0 {
			return sf.userBindMiddlewares.Execute(ctx, write, req, last)
		}
	case statute.CommandAssociate:
		last = sf.handleAssociate
		if sf.userAssociateHandle != nil {
			last = sf.userAssociateHandle
		}
		if len(sf.userAssociateMiddlewares) != 0 {
			return sf.userAssociateMiddlewares.Execute(ctx, write, req, last)
		}
	default:
		if err := handler.SendReply(write, statute.RepCommandNotSupported, nil); err != nil {
			return fmt.Errorf("%w: %w", ErrSendReply, err)
		}
		return fmt.Errorf("%w: %v", ErrUnsupportedCommand, req.Command)
	}
	return last(ctx, write, req)
}

// handleConnect is used to handle a connect command
func (sf *Server) handleConnect(ctx context.Context, writer io.Writer, request *handler.Request) error {
	// Attempt to connect
	var target net.Conn
	var err error

	if sf.dialWithRequest != nil {
		target, err = sf.dialWithRequest(ctx, "tcp", request.DestAddr.String(), request)
	} else {
		dial := sf.dial
		if dial == nil {
			dial = func(ctx context.Context, net_, addr string) (net.Conn, error) {
				return net.Dial(net_, addr)
			}
		}
		target, err = dial(ctx, "tcp", request.DestAddr.String())
	}
	if err != nil {
		msg := err.Error()
		resp := statute.RepHostUnreachable
		if strings.Contains(msg, "refused") {
			resp = statute.RepConnectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = statute.RepNetworkUnreachable
		}
		if err := handler.SendReply(writer, resp, nil); err != nil {
			return fmt.Errorf("%w: %w", ErrSendReply, err)
		}
		return fmt.Errorf("%w to %v: %w", ErrConnectFailed, request.RawDestAddr, err)
	}
	defer target.Close() // nolint: errcheck

	// Send success
	if err := handler.SendReply(writer, statute.RepSuccess, target.LocalAddr()); err != nil {
		return fmt.Errorf("%w: %w", ErrSendReply, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	sf.goFunc(func() { errCh <- sf.ProxyContext(ctx, target, request.Reader) })
	sf.goFunc(func() { errCh <- sf.ProxyContext(ctx, writer, target) })

	for i := 0; i < 2; i++ {
		if e := <-errCh; e != nil && !errors.Is(e, context.Canceled) {
			cancel()
			return e
		}
	}
	return nil
}

// handleBind is used to handle a connect command
func (sf *Server) handleBind(_ context.Context, writer io.Writer, _ *handler.Request) error {
	// TODO: Support bind
	if err := handler.SendReply(writer, statute.RepCommandNotSupported, nil); err != nil {
		return fmt.Errorf("%w: %w", ErrSendReply, err)
	}
	return nil
}

// handleAssociate is used to handle a connect command
func (sf *Server) handleAssociate(ctx context.Context, writer io.Writer, request *handler.Request) error {
	// Attempt to connect
	dial := sf.dial
	if dial == nil {
		dial = func(_ context.Context, net_, addr string) (net.Conn, error) {
			return net.Dial(net_, addr)
		}
	}
	bindLn, err := net.ListenUDP("udp", nil)
	if err != nil {
		if err := handler.SendReply(writer, statute.RepServerFailure, nil); err != nil {
			return fmt.Errorf("%w: %w", ErrSendReply, err)
		}
		return fmt.Errorf("%w: %w", ErrListenUDPFailed, err)
	}

	sf.logger.Errorf("client want to used addr %v, listen addr: %s", request.DestAddr, bindLn.LocalAddr())
	// send BND.ADDR and BND.PORT, client used
	if err = handler.SendReply(writer, statute.RepSuccess, bindLn.LocalAddr()); err != nil {
		return fmt.Errorf("%w: %w", ErrSendReply, err)
	}

	sf.goFunc(func() {
		conns := sync.Map{}
		bufPool := sf.udpBufferPool.Get()
		defer func() {
			sf.udpBufferPool.Put(bufPool)
			bindLn.Close() // nolint: errcheck
			conns.Range(func(key, value any) bool {
				if connTarget, ok := value.(net.Conn); !ok {
					sf.logger.Errorf("conns has illegal item %v:%v", key, value)
				} else {
					connTarget.Close() // nolint: errcheck
				}
				return true
			})
		}()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			n, srcAddr, err := bindLn.ReadFromUDP(bufPool[:cap(bufPool)])
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			pk, err := statute.ParseDatagram(bufPool[:n])
			if err != nil {
				continue
			}

			// check src addr whether equal requst.DestAddr
			srcEqual := ((request.DestAddr.IP.IsUnspecified()) || request.DestAddr.IP.Equal(srcAddr.IP)) && (request.DestAddr.Port == 0 || request.DestAddr.Port == srcAddr.Port) //nolint:lll
			if !srcEqual {
				continue
			}

			connKey := srcAddr.String() + "--" + pk.DstAddr.String()

			if target, ok := conns.Load(connKey); !ok {
				// if the 'connection' doesn't exist, create one and store it
				targetNew, err := dial(ctx, "udp", pk.DstAddr.String())
				if err != nil {
					sf.logger.Errorf("connect to %v failed, %v", pk.DstAddr, err)
					// TODO:continue or return Error?
					continue
				}
				conns.Store(connKey, targetNew)
				// read from remote server and write to original client
				sf.goFunc(func() {
					bufPool := sf.udpBufferPool.Get()
					tmpBufPool := sf.udpBufferPool.Get()
					defer func() {
						targetNew.Close() // nolint: errcheck
						conns.Delete(connKey)
						sf.udpBufferPool.Put(bufPool)
						sf.udpBufferPool.Put(tmpBufPool)
					}()

					for {
						select {
						case <-ctx.Done():
							return
						default:
						}

						buf := bufPool[:cap(bufPool)]
						n, err := targetNew.Read(buf)
						if err != nil {
							if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
								return
							}
							sf.logger.Errorf("read data from remote %s failed, %v", targetNew.RemoteAddr().String(), err)
							return
						}
						proBuf := tmpBufPool[:0]
						proBuf = append(proBuf, pk.Header()...)
						proBuf = append(proBuf, buf[:n]...)
						if _, err := bindLn.WriteTo(proBuf, srcAddr); err != nil {
							sf.logger.Errorf("write data to client %s failed, %v", srcAddr, err)
							return
						}
					}
				})
				if _, err := targetNew.Write(pk.Data); err != nil {
					sf.logger.Errorf("write data to remote server %s failed, %v", targetNew.RemoteAddr().String(), err)
					return
				}
			} else {
				if _, err := target.(net.Conn).Write(pk.Data); err != nil {
					sf.logger.Errorf("write data to remote server %s failed, %v", target.(net.Conn).RemoteAddr().String(), err)
					return
				}
			}
		}
	})

	buf := sf.udpBufferPool.Get()
	defer sf.udpBufferPool.Put(buf)

	for {
		select {
		case <-ctx.Done():
			bindLn.Close() // nolint: errcheck
			return ctx.Err()
		default:
		}
		_, err := request.Reader.Read(buf[:cap(buf)])
		if err != nil {
			bindLn.Close() // nolint: errcheck
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
	}
}

// Proxy is used to shuffle data between src and dst using the internal buffer pool.
func (sf *Server) Proxy(dst io.Writer, src io.Reader) error {
	return sf.ProxyContext(context.Background(), dst, src)
}

// ProxyContext copies data from src to dst respecting ctx.
func (sf *Server) ProxyContext(ctx context.Context, dst io.Writer, src io.Reader) error {
	buf := sf.tcpBufferPool.Get()
	defer sf.tcpBufferPool.Put(buf)
	for {
		select {
		case <-ctx.Done():
			if tcpConn, ok := dst.(closeWriter); ok {
				tcpConn.CloseWrite() //nolint: errcheck
			}
			return ctx.Err()
		default:
			n, err := src.Read(buf[:cap(buf)])
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					if tcpConn, ok := dst.(closeWriter); ok {
						tcpConn.CloseWrite() //nolint: errcheck
					}
					return werr
				}
			}
			if err != nil {
				if tcpConn, ok := dst.(closeWriter); ok {
					tcpConn.CloseWrite() //nolint: errcheck
				}
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
	}
}
