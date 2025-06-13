package socks5

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/things-go/go-socks5/auth"
)

func TestStaticCredentials(t *testing.T) {
	creds := auth.StaticCredentials{
		"foo": "bar",
		"baz": "",
	}

	assert.True(t, creds.Valid("foo", "bar", ""))
	assert.True(t, creds.Valid("baz", "", ""))
	assert.False(t, creds.Valid("foo", "", ""))
}
