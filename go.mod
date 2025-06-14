module github.com/things-go/go-socks5

go 1.18

require (
	github.com/stretchr/testify v1.10.0
	golang.org/x/net v0.35.0
)

replace github.com/rs/zerolog => ./internal/zerolog

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rs/zerolog v1.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
