package main

import (
	"os"

	"github.com/rs/zerolog"

	"github.com/things-go/go-socks5"
)

func main() {
	// Create a SOCKS5 server
	logger := zerolog.New(os.Stdout)
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(logger)),
	)

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", ":10800"); err != nil {
		panic(err)
	}
}
