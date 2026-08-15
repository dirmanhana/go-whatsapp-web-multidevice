package auth

import (
	"context"
	"time"

	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
)

type RegisterRequest struct {
	// Email enables self-service registration: an account can be created
	// with email + password only, and the username is derived from the
	// email's local part. May be empty for legacy username-only clients.
	Email string `json:"email"`
	// Username is optional when Email is present (derived from it).
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginRequest struct {
	// Username doubles as the login identifier: either the username or the
	// registered email is accepted.
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserInfo struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	DeviceCount int    `json:"device_count"`
	IsAdmin     bool   `json:"is_admin"`
}

// AdminUserInfo is the admin's view of one account: identity, flags, device
// count, and registration time.
type AdminUserInfo struct {
	ID          int64     `json:"id"`
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	IsAdmin     bool      `json:"is_admin"`
	Disabled    bool      `json:"disabled"`
	DeviceCount int       `json:"device_count"`
	CreatedAt   time.Time `json:"created_at"`
}

type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      UserInfo  `json:"user"`
}

// SessionInfo is a masked view of one issued auth session. TokenID is the
// prefix of the stored token digest, stable across calls but not usable as
// a credential.
type SessionInfo struct {
	TokenID   string    `json:"token_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Expired   bool      `json:"expired"`
}

type IAuthUsecase interface {
	// Register creates a new user account when AuthAllowRegister is enabled.
	Register(ctx context.Context, request RegisterRequest) (UserInfo, error)
	// Login validates credentials and issues a Bearer token.
	Login(ctx context.Context, request LoginRequest) (LoginResponse, error)
	// Logout revokes the given token.
	Logout(ctx context.Context, token string) error
	// Sessions lists the authenticated user's active sessions (masked).
	Sessions(ctx context.Context) ([]SessionInfo, error)
	// LogoutAll revokes every session of the authenticated user.
	LogoutAll(ctx context.Context) error
	// Authenticate resolves a token to its user, or fails with ErrUnauthorized.
	Authenticate(ctx context.Context, token string) (*domainChatStorage.User, error)
	// AuthenticateBasic validates dashboard-style Basic credentials
	// (username + password) and resolves the user, or fails with
	// ErrUnauthorized. No token is issued.
	AuthenticateBasic(ctx context.Context, username, password string) (*domainChatStorage.User, error)
	// Me returns the authenticated user from the request context with its
	// current device count.
	Me(ctx context.Context) (UserInfo, error)
	// ListUsers returns all accounts; admin only.
	ListUsers(ctx context.Context) ([]AdminUserInfo, error)
	// SetUserDisabled enables or disables an account (ban); admin only.
	// Disabling revokes the user's sessions.
	SetUserDisabled(ctx context.Context, userID int64, disabled bool) error
}
