package socks5

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/rs/zerolog"

	"github.com/things-go/go-socks5/auth"
	"github.com/things-go/go-socks5/bufferpool"
	"github.com/things-go/go-socks5/handler"
	"github.com/things-go/go-socks5/resolver"
	"github.com/things-go/go-socks5/rule"
	"github.com/things-go/go-socks5/statute"
)

// GPool is used to implement custom goroutine pool default use goroutine
type GPool interface {
	Submit(f func()) error
}

// Server is responsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	// authMethods can be provided to implement authentication
	// By default, "no-auth" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	authMethods []auth.Authenticator
	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and authMethods is nil, then "no-auth" mode is enabled.
	credentials auth.CredentialStore
	// resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	resolver resolver.NameResolver
	// rules is provided to enable custom logic around permitting
	// various commands. If not provided, NewPermitAll is used.
	rules rule.RuleSet
	// rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	rewriter handler.AddressRewriter
	// bindIP is used for bind or udp associate
	bindIP net.IP
	// logger can be used to provide a custom log target.
	// Defaults to io.Discard.
	logger Logger
	// Optional function for dialing out.
	// The callback set by dialWithRequest will be called first.
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Optional function for dialing out with the access of request detail.
	dialWithRequest func(ctx context.Context, network, addr string, request *handler.Request) (net.Conn, error)
	// tcpBufferPool is used for TCP connection proxying
	tcpBufferPool bufferpool.BufPool
	// udpBufferPool is used for UDP associate handling
	udpBufferPool bufferpool.BufPool
	// goroutine pool
	gPool GPool
	// user's handle
	userConnectHandle   func(ctx context.Context, writer io.Writer, request *handler.Request) error
	userBindHandle      func(ctx context.Context, writer io.Writer, request *handler.Request) error
	userAssociateHandle func(ctx context.Context, writer io.Writer, request *handler.Request) error
	// user's middleware
	userConnectMiddlewares   MiddlewareChain
	userBindMiddlewares      MiddlewareChain
	userAssociateMiddlewares MiddlewareChain
	// timeout for handling each connection and dialing out
	timeout time.Duration
}

// NewServer creates a new Server
func NewServer(opts ...Option) *Server {
	srv := &Server{
		authMethods:   []auth.Authenticator{},
		tcpBufferPool: bufferpool.NewPool(32 * 1024),
		udpBufferPool: bufferpool.NewPool(32 * 1024),
		resolver:      resolver.DNSResolver{},
		rules:         rule.NewPermitAll(),
		logger:        NewLogger(zerolog.New(io.Discard)),
	}

	for _, opt := range opts {
		opt(srv)
	}

	// Ensure we have at least one authentication method enabled
	if (len(srv.authMethods) == 0) && srv.credentials != nil {
		srv.authMethods = []auth.Authenticator{&auth.UserPassAuthenticator{Credentials: srv.credentials}}
	}
	if len(srv.authMethods) == 0 {
		srv.authMethods = []auth.Authenticator{&auth.NoAuthAuthenticator{}}
	}

	return srv
}

// ListenAndServe is used to create a listener and serve on it
func (sf *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return sf.Serve(l)
}

// ListenAndServeTLS is used to create a TLS listener and serve on it
func (sf *Server) ListenAndServeTLS(network, addr string, c *tls.Config) error {
	l, err := tls.Listen(network, addr, c)
	if err != nil {
		return err
	}
	return sf.Serve(l)
}

// Serve is used to serve connections from a listener
func (sf *Server) Serve(l net.Listener) error {
	defer l.Close() // nolint: errcheck
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		sf.goFunc(func() {
			if err := sf.ServeConn(conn); err != nil {
				sf.logger.Errorf("server: %v", err)
			}
		})
	}
}

// ServeConn is used to serve a single connection.
func (sf *Server) ServeConn(conn net.Conn) error {
	var authContext *auth.AuthContext

	defer conn.Close() // nolint: errcheck
	if sf.timeout > 0 {
		conn.SetDeadline(time.Now().Add(sf.timeout)) //nolint: errcheck
		defer conn.SetDeadline(time.Time{})          //nolint: errcheck
	}

	bufConn := bufio.NewReader(conn)

	mr, err := statute.ParseMethodRequest(bufConn)
	if err != nil {
		return err
	}
	if mr.Ver != statute.VersionSocks5 {
		return statute.ErrNotSupportVersion
	}

	// Authenticate the connection
	userAddr := ""
	if conn.RemoteAddr() != nil {
		userAddr = conn.RemoteAddr().String()
	}
	authContext, err = sf.authenticate(conn, bufConn, userAddr, mr.Methods)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrAuthFailed, err)
	}

	// The client request detail
	request, err := handler.ParseRequest(bufConn)
	if err != nil {
		if errors.Is(err, statute.ErrUnrecognizedAddrType) {
			if err := handler.SendReply(conn, statute.RepAddrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("%w: %w", ErrSendReply, err)
			}
		}
		return fmt.Errorf("%w: %w", ErrReadDestination, err)
	}

	if request.Request.Command != statute.CommandConnect && // nolint: staticcheck
		request.Request.Command != statute.CommandBind && // nolint: staticcheck
		request.Request.Command != statute.CommandAssociate { // nolint: staticcheck
		if err := handler.SendReply(conn, statute.RepCommandNotSupported, nil); err != nil {
			return fmt.Errorf("%w: %w", ErrSendReply, err)
		}
		return fmt.Errorf("%w: %d", ErrUnsupportedCommand, request.Request.Command) // nolint: staticcheck
	}

	request.AuthContext = authContext
	request.LocalAddr = conn.LocalAddr()
	request.RemoteAddr = conn.RemoteAddr()
	// Process the client request
	return sf.handleRequest(conn, request)
}

// authenticate is used to handle connection authentication
func (sf *Server) authenticate(conn io.Writer, bufConn io.Reader,
	userAddr string, methods []byte) (*auth.AuthContext, error) {
	// Select a usable method
	for _, auth := range sf.authMethods {
		for _, method := range methods {
			if auth.GetCode() == method {
				return auth.Authenticate(bufConn, conn, userAddr)
			}
		}
	}
	// No usable method found
	conn.Write([]byte{statute.VersionSocks5, statute.MethodNoAcceptable}) //nolint: errcheck
	return nil, statute.ErrNoSupportedAuth
}

func (sf *Server) goFunc(f func()) {
	if sf.gPool == nil || sf.gPool.Submit(f) != nil {
		go f()
	}
}
