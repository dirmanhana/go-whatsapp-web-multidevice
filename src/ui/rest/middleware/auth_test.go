package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubTokenAuthenticator struct {
	user *domainChatStorage.User
	err  error
}

func (s *stubTokenAuthenticator) Authenticate(_ context.Context, token string) (*domainChatStorage.User, error) {
	return s.user, s.err
}

func (s *stubTokenAuthenticator) AuthenticateBasic(_ context.Context, username, password string) (*domainChatStorage.User, error) {
	return s.user, s.err
}

func newAuthTestApp(auth TokenAuthenticator) *fiber.App {
	app := fiber.New()
	app.Use(AuthMiddleware(auth))
	app.Get("/protected", func(c fiber.Ctx) error {
		user, ok := domainChatStorage.UserFromContext(c.Context())
		if !ok || user == nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}
		return c.SendString(user.Username)
	})
	app.Post("/auth/register", func(c fiber.Ctx) error {
		return c.SendString("public-register")
	})
	return app
}

func TestAuthMiddlewareFlow(t *testing.T) {
	// Save/restore config because AuthMiddleware reads the global flag.
	prev := config.AuthEnabled
	config.AuthEnabled = true
	defer func() { config.AuthEnabled = prev }()

	app := newAuthTestApp(&stubTokenAuthenticator{
		user: &domainChatStorage.User{ID: 3, Username: "alice"},
	})

	t.Run("rejects missing token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/protected", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("rejects invalid token", func(t *testing.T) {
		app2 := newAuthTestApp(&stubTokenAuthenticator{err: errors.New("bad")})
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer nope")
		resp, err := app2.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("accepts valid token and injects user", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set(fiber.HeaderAuthorization, "Bearer valid-token")
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "alice", string(body))
	})

	t.Run("public paths pass through", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/auth/register", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "public-register", string(body))
	})

	t.Run("accepts Basic credentials", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set(fiber.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))
		resp, err := app.Test(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, fiber.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "alice", string(body))
	})

	t.Run("rejects invalid Basic credentials", func(t *testing.T) {
		bad := newAuthTestApp(&stubTokenAuthenticator{err: errors.New("bad")})
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set(fiber.HeaderAuthorization, "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:wrong")))
		resp, err := bad.Test(req)
		require.NoError(t, err)
		assert.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})
}

func TestAuthMiddlewareDisabledPassesThrough(t *testing.T) {
	prev := config.AuthEnabled
	config.AuthEnabled = false
	defer func() { config.AuthEnabled = prev }()

	app := newAuthTestApp(nil)
	req := httptest.NewRequest("GET", "/protected", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	// No user in context with auth disabled → handler returns 500, but the
	// middleware must NOT have rejected the request.
	assert.Equal(t, fiber.StatusInternalServerError, resp.StatusCode)
	resp.Body.Close()
}

func TestBearerToken(t *testing.T) {
	assert.Equal(t, "abc123", BearerToken("Bearer abc123"))
	assert.Equal(t, "abc123", BearerToken("bearer abc123"))
	assert.Equal(t, "", BearerToken("Basic abc123"))
	assert.Equal(t, "", BearerToken(""))
	assert.Equal(t, "", BearerToken("Bearer"))
	assert.Equal(t, "x", BearerToken("Bearer x"))
}

func TestBasicCredentials(t *testing.T) {
	enc := func(s string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(s))
	}
	u, p := BasicCredentials(enc("alice:secret"))
	assert.Equal(t, "alice", u)
	assert.Equal(t, "secret", p)

	u, p = BasicCredentials(enc("alice"))
	assert.Equal(t, "", u)
	assert.Equal(t, "", p)

	u, p = BasicCredentials("Bearer abc")
	assert.Equal(t, "", u)
	assert.Equal(t, "", p)

	u, p = BasicCredentials("Basic not-base64!!!")
	assert.Equal(t, "", u)
	assert.Equal(t, "", p)

	u, p = BasicCredentials("")
	assert.Equal(t, "", u)
	assert.Equal(t, "", p)

	// Passwords may contain colons.
	u, p = BasicCredentials(enc("alice:p:a:ss"))
	assert.Equal(t, "alice", u)
	assert.Equal(t, "p:a:ss", p)
}