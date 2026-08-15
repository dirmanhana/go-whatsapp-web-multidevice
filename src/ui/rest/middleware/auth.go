package middleware

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/utils"
	"github.com/gofiber/fiber/v3"
)

// TokenAuthenticator is the subset of the auth usecase the middleware needs.
// Satisfied structurally by usecase.NewAuthService.
type TokenAuthenticator interface {
	Authenticate(ctx context.Context, token string) (*domainChatStorage.User, error)
}

// BasicAuthenticator validates dashboard-style username/password credentials.
// It is optional: AuthMiddleware only uses it when the request carries an
// "Authorization: Basic" header. Satisfied structurally by usecase.NewAuthService.
type BasicAuthenticator interface {
	AuthenticateBasic(ctx context.Context, username, password string) (*domainChatStorage.User, error)
}

// BearerToken extracts the token from an Authorization header value
// ("Bearer <token>"), or "" when absent or malformed.
func BearerToken(authorization string) string {
	authorization = strings.TrimSpace(authorization)
	const prefix = "Bearer "
	if len(authorization) > len(prefix) && strings.EqualFold(authorization[:len(prefix)], prefix) {
		return strings.TrimSpace(authorization[len(prefix):])
	}
	return ""
}

// BasicCredentials extracts the username/password pair from an "Authorization:
// Basic base64(user:pass)" header value. Returns empty strings when absent or
// malformed.
func BasicCredentials(authorization string) (username, password string) {
	authorization = strings.TrimSpace(authorization)
	const prefix = "Basic "
	if len(authorization) <= len(prefix) || !strings.EqualFold(authorization[:len(prefix)], prefix) {
		return "", ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(authorization[len(prefix):]))
	if err != nil {
		return "", ""
	}
	credentials := string(raw)
	sep := strings.IndexByte(credentials, ':')
	if sep < 0 {
		return "", ""
	}
	return credentials[:sep], credentials[sep+1:]
}

// AuthMiddleware protects the API behind authentication when
// config.AuthEnabled. Both Bearer tokens (programmatic clients) and Basic
// credentials (browser dashboard) are accepted. Public paths (landing page,
// register, login) pass through; every other path requires a valid identity.
// The authenticated user is attached to the request context
// (domainChatStorage.UserFromContext) and to the locals ("user", "user_id").
func AuthMiddleware(auth TokenAuthenticator) fiber.Handler {
	return func(c fiber.Ctx) error {
		if !config.AuthEnabled {
			return c.Next()
		}

		path := strings.TrimSpace(c.Path())
		if isPublicAuthPath(path) {
			return c.Next()
		}

		if auth == nil {
			return unauthorizedResponse(c)
		}

		var user *domainChatStorage.User
		if token := BearerToken(c.Get(fiber.HeaderAuthorization)); token != "" {
			u, err := auth.Authenticate(c.Context(), token)
			if err == nil && u != nil {
				user = u
			}
		} else if basic, ok := auth.(BasicAuthenticator); ok {
			username, password := BasicCredentials(c.Get(fiber.HeaderAuthorization))
			if username != "" {
				u, err := basic.AuthenticateBasic(c.Context(), username, password)
				if err == nil && u != nil {
					user = u
				}
			}
		}

		if user == nil {
			// The dashboard's auto-connect probe (GET /devices with NO
			// credentials at all) must succeed so it can derive the server
			// URL from its own origin; the handler returns an empty list for
			// unauthenticated callers. Requests carrying (wrong) credentials
			// still fail with 401 so clients can detect auth errors.
			if c.Get(fiber.HeaderAuthorization) == "" && c.Method() == fiber.MethodGet && isDevicesProbePath(strings.TrimSpace(c.Path())) {
				return c.Next()
			}
			return unauthorizedResponse(c)
		}

		c.Locals("user", user)
		c.Locals("user_id", user.ID)
		c.SetContext(domainChatStorage.ContextWithUser(c.Context(), user))
		return c.Next()
	}
}

// isPublicAuthPath reports whether a path stays reachable without a token in
// multi-user mode: the landing page/UI root and the register/login endpoints.
func isPublicAuthPath(path string) bool {
	if path == "/" || path == "" || path == config.AppBasePath || path == config.AppBasePath+"/" {
		return true
	}
	return strings.HasSuffix(path, "/auth/register") || strings.HasSuffix(path, "/auth/login")
}

func unauthorizedResponse(c fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(utils.ResponseData{
		Status:  fiber.StatusUnauthorized,
		Code:    "UNAUTHORIZED",
		Message: "authentication required: login via POST /auth/login and send the token as 'Authorization: Bearer <token>'",
		Results: nil,
	})
}