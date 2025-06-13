package socks5

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/things-go/go-socks5/resolver"
)

func TestDNSResolver(t *testing.T) {
	d := resolver.DNSResolver{}
	ctx := context.Background()

	_, addr, err := d.Resolve(ctx, "localhost")
	require.NoError(t, err)
	assert.True(t, addr.IsLoopback())
}

type mockResolver struct {
	mu    sync.Mutex
	count int
}

func (m *mockResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	m.mu.Lock()
	m.count++
	m.mu.Unlock()
	return ctx, net.IPv4(127, 0, 0, 1), nil
}

func TestCachingResolver(t *testing.T) {
	base := &mockResolver{}
	c := resolver.NewCachingResolver(base, 50*time.Millisecond)
	ctx := context.Background()

	_, ip1, err := c.Resolve(ctx, "localhost")
	require.NoError(t, err)
	assert.True(t, ip1.IsLoopback())

	_, ip2, err := c.Resolve(ctx, "localhost")
	require.NoError(t, err)
	assert.True(t, ip2.Equal(ip1))
	assert.Equal(t, 1, base.count)

	time.Sleep(60 * time.Millisecond)
	_, _, _ = c.Resolve(ctx, "localhost")
	assert.Equal(t, 2, base.count)
}
