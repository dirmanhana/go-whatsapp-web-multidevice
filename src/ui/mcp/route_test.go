package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubMCPAuthenticator satisfies both middleware.TokenAuthenticator and
// middleware.BasicAuthenticator, like usecase.NewAuthService does.
type stubMCPAuthenticator struct {
	user *domainChatStorage.User
	err  error
}

func (s *stubMCPAuthenticator) Authenticate(_ context.Context, _ string) (*domainChatStorage.User, error) {
	return s.user, s.err
}

func (s *stubMCPAuthenticator) AuthenticateBasic(_ context.Context, _, _ string) (*domainChatStorage.User, error) {
	return s.user, s.err
}

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func TestAuthenticateMCPUser(t *testing.T) {
	alice := &domainChatStorage.User{ID: 3, Username: "alice"}
	auth := &stubMCPAuthenticator{user: alice}

	t.Run("nil auth service yields no user", func(t *testing.T) {
		user, err := authenticateMCPUser(context.Background(), nil, "Bearer abc")
		require.NoError(t, err)
		assert.Nil(t, user)
	})

	t.Run("empty authorization yields no user", func(t *testing.T) {
		user, err := authenticateMCPUser(context.Background(), auth, "")
		require.NoError(t, err)
		assert.Nil(t, user)
	})

	t.Run("bearer token authenticates", func(t *testing.T) {
		user, err := authenticateMCPUser(context.Background(), auth, "Bearer abc123")
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, "alice", user.Username)
	})

	t.Run("basic credentials authenticate", func(t *testing.T) {
		user, err := authenticateMCPUser(context.Background(), auth, basicHeader("alice", "secret"))
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, "alice", user.Username)
	})

	t.Run("failed bearer surfaces the error", func(t *testing.T) {
		bad := &stubMCPAuthenticator{err: errors.New("invalid token")}
		user, err := authenticateMCPUser(context.Background(), bad, "Bearer nope")
		require.Error(t, err)
		assert.Nil(t, user)
	})

	t.Run("failed basic surfaces the error", func(t *testing.T) {
		bad := &stubMCPAuthenticator{err: errors.New("invalid credentials")}
		user, err := authenticateMCPUser(context.Background(), bad, basicHeader("alice", "wrong"))
		require.Error(t, err)
		assert.Nil(t, user)
	})
}