package auth

import (
	"context"
	"time"

	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
)

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserInfo struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	DeviceCount int    `json:"device_count"`
}

type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      UserInfo  `json:"user"`
}

type IAuthUsecase interface {
	// Register creates a new user account when AuthAllowRegister is enabled.
	Register(ctx context.Context, request RegisterRequest) (UserInfo, error)
	// Login validates credentials and issues a Bearer token.
	Login(ctx context.Context, request LoginRequest) (LoginResponse, error)
	// Logout revokes the given token.
	Logout(ctx context.Context, token string) error
	// Authenticate resolves a token to its user, or fails with ErrUnauthorized.
	Authenticate(ctx context.Context, token string) (*domainChatStorage.User, error)
	// AuthenticateBasic validates dashboard-style Basic credentials
	// (username + password) and resolves the user, or fails with
	// ErrUnauthorized. No token is issued.
	AuthenticateBasic(ctx context.Context, username, password string) (*domainChatStorage.User, error)
	// Me returns the authenticated user from the request context with its
	// current device count.
	Me(ctx context.Context) (UserInfo, error)
}
