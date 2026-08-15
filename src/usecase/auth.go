package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	domainAuth "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/auth"
	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
	pkgError "github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/error"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/validations"
	fiberUtils "github.com/gofiber/utils/v2"
	"golang.org/x/crypto/bcrypt"
)

type serviceAuth struct {
	storage domainChatStorage.IChatStorageRepository
}

func NewAuthService(storage domainChatStorage.IChatStorageRepository) domainAuth.IAuthUsecase {
	return &serviceAuth{storage: storage}
}

func (s *serviceAuth) Register(ctx context.Context, request domainAuth.RegisterRequest) (domainAuth.UserInfo, error) {
	var info domainAuth.UserInfo
	if err := validations.ValidateRegisterRequest(ctx, request); err != nil {
		return info, err
	}
	if !config.AuthAllowRegister {
		return info, pkgError.ErrRegistrationBlocked
	}
	if s.storage == nil {
		return info, fmt.Errorf("chat storage not initialized")
	}

	username := strings.TrimSpace(request.Username)
	existing, err := s.storage.GetUserByUsername(username)
	if err != nil {
		return info, err
	}
	if existing != nil {
		return info, pkgError.ErrUserAlreadyExists
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return info, fmt.Errorf("failed to hash password: %w", err)
	}

	// Admin bootstrap: either the first account ever (fresh deployment) or
	// the account matching the operator-designated AUTH_ADMIN_USERNAME.
	userCount, err := s.storage.CountUsers()
	if err != nil {
		return info, err
	}
	isAdmin := userCount == 0 || matchesAdminUsername(username)

	id, err := s.storage.CreateUser(username, string(passwordHash))
	if err != nil {
		return info, err
	}
	if isAdmin {
		if err := s.storage.SetUserAdmin(id, true); err != nil {
			return info, err
		}
	}

	return domainAuth.UserInfo{ID: id, Username: username, DeviceCount: 0, IsAdmin: isAdmin}, nil
}

func (s *serviceAuth) Login(ctx context.Context, request domainAuth.LoginRequest) (domainAuth.LoginResponse, error) {
	var response domainAuth.LoginResponse
	if err := validations.ValidateLoginRequest(ctx, request); err != nil {
		return response, err
	}
	if s.storage == nil {
		return response, fmt.Errorf("chat storage not initialized")
	}

	user, err := s.storage.GetUserByUsername(strings.TrimSpace(request.Username))
	if err != nil {
		return response, err
	}
	if user == nil {
		return response, pkgError.ErrInvalidCredentials
	}
	if user.Disabled {
		return response, pkgError.ErrUserDisabled
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)); err != nil {
		return response, pkgError.ErrInvalidCredentials
	}

	// Re-verify the operator-designated admin on every login so an existing
	// deployment can promote an account without re-registering.
	if matchesAdminUsername(user.Username) && !user.IsAdmin {
		if err := s.storage.SetUserAdmin(user.ID, true); err != nil {
			return response, err
		}
		user.IsAdmin = true
	}

	// Opportunistic cleanup of stale tokens before issuing a new one.
	_ = s.storage.DeleteExpiredAuthTokens()

	token := generateAuthToken()
	expiresAt := time.Now().Add(config.AuthTokenTTL)
	if err := s.storage.CreateAuthToken(hashAuthToken(token), user.ID, expiresAt); err != nil {
		return response, err
	}

	deviceCount, _ := s.storage.CountUserDevices(user.ID)
	response = domainAuth.LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User: domainAuth.UserInfo{
			ID:          user.ID,
			Username:    user.Username,
			DeviceCount: deviceCount,
			IsAdmin:     user.IsAdmin,
		},
	}
	return response, nil
}

func (s *serviceAuth) Logout(_ context.Context, token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return pkgError.ErrUnauthorized
	}
	if s.storage == nil {
		return fmt.Errorf("chat storage not initialized")
	}
	return s.storage.DeleteAuthToken(hashAuthToken(token))
}

// Sessions lists the authenticated user's sessions with masked token ids,
// newest first, so clients can audit where tokens are active without any
// usable credential leaving the server.
func (s *serviceAuth) Sessions(ctx context.Context) ([]domainAuth.SessionInfo, error) {
	user, ok := domainChatStorage.UserFromContext(ctx)
	if !ok || user == nil {
		return nil, pkgError.ErrUnauthorized
	}
	if s.storage == nil {
		return nil, fmt.Errorf("chat storage not initialized")
	}

	tokens, err := s.storage.ListAuthTokens(user.ID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	sessions := make([]domainAuth.SessionInfo, 0, len(tokens))
	for _, token := range tokens {
		sessions = append(sessions, domainAuth.SessionInfo{
			TokenID:   maskAuthTokenHash(token.TokenHash),
			CreatedAt: token.CreatedAt,
			ExpiresAt: token.ExpiresAt,
			Expired:   token.ExpiresAt.Before(now),
		})
	}
	return sessions, nil
}

// LogoutAll revokes every session of the authenticated user, including the
// one used for this request.
func (s *serviceAuth) LogoutAll(ctx context.Context) error {
	user, ok := domainChatStorage.UserFromContext(ctx)
	if !ok || user == nil {
		return pkgError.ErrUnauthorized
	}
	if s.storage == nil {
		return fmt.Errorf("chat storage not initialized")
	}
	return s.storage.DeleteUserAuthTokens(user.ID)
}

func (s *serviceAuth) Authenticate(_ context.Context, token string) (*domainChatStorage.User, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, pkgError.ErrUnauthorized
	}
	if s.storage == nil {
		return nil, pkgError.ErrUnauthorized
	}

	user, err := s.storage.GetUserByTokenHash(hashAuthToken(token))
	if err != nil {
		return nil, err
	}
	if user == nil || user.Disabled {
		return nil, pkgError.ErrUnauthorized
	}
	return user, nil
}

// AuthenticateBasic validates plain username/password credentials (the
// browser dashboard sends these as HTTP Basic auth on every request). It is
// intentionally token-free: no auth_tokens row is created.
func (s *serviceAuth) AuthenticateBasic(_ context.Context, username, password string) (*domainChatStorage.User, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, pkgError.ErrUnauthorized
	}
	if s.storage == nil {
		return nil, pkgError.ErrUnauthorized
	}

	user, err := s.storage.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, pkgError.ErrUnauthorized
	}
	if user.Disabled {
		return nil, pkgError.ErrUserDisabled
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, pkgError.ErrUnauthorized
	}
	return user, nil
}

func (s *serviceAuth) Me(ctx context.Context) (domainAuth.UserInfo, error) {
	var info domainAuth.UserInfo
	if !config.AuthEnabled {
		return info, pkgError.ErrUnauthorized
	}
	user, ok := domainChatStorage.UserFromContext(ctx)
	if !ok || user == nil {
		return info, pkgError.ErrUnauthorized
	}
	deviceCount, err := s.storage.CountUserDevices(user.ID)
	if err != nil {
		return info, err
	}
	return domainAuth.UserInfo{
		ID:          user.ID,
		Username:    user.Username,
		DeviceCount: deviceCount,
		IsAdmin:     user.IsAdmin,
	}, nil
}

// ListUsers returns every account for an admin caller.
func (s *serviceAuth) ListUsers(ctx context.Context) ([]domainAuth.AdminUserInfo, error) {
	if _, err := s.requireAdmin(ctx); err != nil {
		return nil, err
	}
	if s.storage == nil {
		return nil, fmt.Errorf("chat storage not initialized")
	}

	users, err := s.storage.ListUsers()
	if err != nil {
		return nil, err
	}
	result := make([]domainAuth.AdminUserInfo, 0, len(users))
	for _, user := range users {
		deviceCount, _ := s.storage.CountUserDevices(user.ID)
		result = append(result, domainAuth.AdminUserInfo{
			ID:          user.ID,
			Username:    user.Username,
			IsAdmin:     user.IsAdmin,
			Disabled:    user.Disabled,
			DeviceCount: deviceCount,
			CreatedAt:   user.CreatedAt,
		})
	}
	return result, nil
}

// SetUserDisabled bans or unbans an account for an admin caller. Disabling
// also revokes every session of the target user; an admin can never disable
// their own account.
func (s *serviceAuth) SetUserDisabled(ctx context.Context, userID int64, disabled bool) error {
	caller, err := s.requireAdmin(ctx)
	if err != nil {
		return err
	}
	if s.storage == nil {
		return fmt.Errorf("chat storage not initialized")
	}
	if caller.ID == userID {
		return pkgError.ErrCannotDisableSelf
	}

	if err := s.storage.SetUserDisabled(userID, disabled); err != nil {
		return err
	}
	if disabled {
		// Sessions must die with the ban; re-enabling starts from a clean slate.
		return s.storage.DeleteUserAuthTokens(userID)
	}
	return nil
}

// requireAdmin resolves the caller from the request context and enforces the
// admin flag.
func (s *serviceAuth) requireAdmin(ctx context.Context) (*domainChatStorage.User, error) {
	user, ok := domainChatStorage.UserFromContext(ctx)
	if !ok || user == nil {
		return nil, pkgError.ErrUnauthorized
	}
	if !user.IsAdmin {
		return nil, pkgError.ErrForbidden
	}
	return user, nil
}

// matchesAdminUsername reports whether the username equals the operator-
// designated AUTH_ADMIN_USERNAME (case-insensitive). An empty designation
// never matches, so bootstrap falls back to the first registered user.
func matchesAdminUsername(username string) bool {
	return config.AuthAdminUsername != "" && strings.EqualFold(strings.TrimSpace(username), strings.TrimSpace(config.AuthAdminUsername))
}

// generateAuthToken returns a 64-char hex token (32 random bytes). Only the
// SHA-256 digest is persisted, so a DB leak does not expose usable tokens.
func generateAuthToken() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand never fails on supported platforms; keep a best-effort
		// fallback so a broken platform degrades instead of panicking.
		return fmt.Sprintf("%d-%s", time.Now().UnixNano(), fiberUtils.UUID())
	}
	return hex.EncodeToString(buf)
}

func hashAuthToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// maskAuthTokenHash renders a stable display id for a session row without
// exposing the full stored digest: "cafebabe...".
func maskAuthTokenHash(tokenHash string) string {
	if len(tokenHash) <= 8 {
		return tokenHash
	}
	return tokenHash[:8] + "..."
}