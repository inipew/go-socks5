package socks5

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/things-go/go-socks5/handler"
	"github.com/things-go/go-socks5/rule"
	"github.com/things-go/go-socks5/statute"
)

func TestPermitCommand(t *testing.T) {
	var r rule.RuleSet
	var ok bool

	ctx := context.Background()

	r = rule.NewPermitAll()
	_, ok = r.Allow(ctx, &handler.Request{Request: statute.Request{Command: statute.CommandConnect}})
	require.True(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: statute.Request{Command: statute.CommandBind}})
	require.True(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: statute.Request{Command: statute.CommandAssociate}})
	require.True(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: statute.Request{Command: 0x00}})
	require.False(t, ok)

	r = rule.NewPermitConnAndAss()
	_, ok = r.Allow(ctx, &handler.Request{Request: statute.Request{Command: statute.CommandConnect}})
	require.True(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: statute.Request{Command: statute.CommandBind}})
	require.False(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: statute.Request{Command: statute.CommandAssociate}})
	require.True(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: statute.Request{Command: 0x00}})
	require.False(t, ok)

	r = rule.NewPermitNone()
	_, ok = r.Allow(ctx, &handler.Request{Request: statute.Request{Command: statute.CommandConnect}})
	require.False(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: statute.Request{Command: statute.CommandBind}})
	require.False(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: statute.Request{Command: statute.CommandAssociate}})
	require.False(t, ok)
	_, ok = r.Allow(ctx, &handler.Request{Request: statute.Request{Command: 0x00}})
	require.False(t, ok)
}
