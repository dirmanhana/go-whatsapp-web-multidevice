package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
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
	email := strings.TrimSpace(request.Email)

	// Self-service registration: a username is derived from the email's local
	// part when the client only sends email + password.
	if username == "" {
		username = s.deriveUsernameFromEmail(email)
	}

	existing, err := s.storage.GetUserByUsername(username)
	if err != nil {
		return info, err
	}
	if existing != nil {
		return info, pkgError.ErrUserAlreadyExists
	}
	if email != "" {
		existingByEmail, err := s.storage.GetUserByEmail(email)
		if err != nil {
			return info, err
		}
		if existingByEmail != nil {
			return info, pkgError.ErrEmailAlreadyExists
		}
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

	id, err := s.storage.CreateUser(username, email, string(passwordHash))
	if err != nil {
		return info, err
	}
	if isAdmin {
		if err := s.storage.SetUserAdmin(id, true); err != nil {
			return info, err
		}
	}

	return domainAuth.UserInfo{ID: id, Username: username, Email: email, DeviceCount: 0, IsAdmin: isAdmin}, nil
}

func (s *serviceAuth) Login(ctx context.Context, request domainAuth.LoginRequest) (domainAuth.LoginResponse, error) {
	var response domainAuth.LoginResponse
	if err := validations.ValidateLoginRequest(ctx, request); err != nil {
		return response, err
	}
	if s.storage == nil {
		return response, fmt.Errorf("chat storage not initialized")
	}

	identifier := strings.TrimSpace(request.Username)
	user, err := s.storage.GetUserByUsername(identifier)
	if err != nil {
		return response, err
	}
	if user == nil {
		// The identifier may also be the registered email.
		user, err = s.storage.GetUserByEmail(identifier)
		if err != nil {
			return response, err
		}
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
			Email:       user.Email,
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
		// The identifier may also be the registered email.
		user, err = s.storage.GetUserByEmail(username)
		if err != nil {
			return nil, err
		}
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
		Email:       user.Email,
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
			Email:       user.Email,
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

// AdminCreateUser provisions an account chosen by an admin. Unlike Register
// it is not gated by AuthAllowRegister: an operator always may create accounts
// for their users, and may flag the new account as admin directly.
func (s *serviceAuth) AdminCreateUser(ctx context.Context, request domainAuth.AdminCreateUserRequest) (domainAuth.AdminUserInfo, error) {
	var info domainAuth.AdminUserInfo
	if _, err := s.requireAdmin(ctx); err != nil {
		return info, err
	}
	if err := validations.ValidateAdminCreateUserRequest(ctx, request); err != nil {
		return info, err
	}
	if s.storage == nil {
		return info, fmt.Errorf("chat storage not initialized")
	}

	username := strings.TrimSpace(request.Username)
	email := strings.TrimSpace(request.Email)
	if username == "" {
		username = s.deriveUsernameFromEmail(email)
	}

	if existing, err := s.storage.GetUserByUsername(username); err != nil {
		return info, err
	} else if existing != nil {
		return info, pkgError.ErrUserAlreadyExists
	}
	if email != "" {
		if existingByEmail, err := s.storage.GetUserByEmail(email); err != nil {
			return info, err
		} else if existingByEmail != nil {
			return info, pkgError.ErrEmailAlreadyExists
		}
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return info, fmt.Errorf("failed to hash password: %w", err)
	}

	id, err := s.storage.CreateUser(username, email, string(passwordHash))
	if err != nil {
		return info, err
	}
	if request.IsAdmin {
		if err := s.storage.SetUserAdmin(id, true); err != nil {
			return info, err
		}
	}
	return s.adminInfo(id)
}

// AdminUpdateUser edits an account's username, email, or admin flag. Pointer
// fields name exactly what changed; omitted fields keep their current value.
func (s *serviceAuth) AdminUpdateUser(ctx context.Context, userID int64, request domainAuth.AdminUpdateUserRequest) (domainAuth.AdminUserInfo, error) {
	var info domainAuth.AdminUserInfo
	caller, err := s.requireAdmin(ctx)
	if err != nil {
		return info, err
	}
	if err := validations.ValidateAdminUpdateUserRequest(ctx, request); err != nil {
		return info, err
	}
	if s.storage == nil {
		return info, fmt.Errorf("chat storage not initialized")
	}

	target, err := s.storage.GetUserByID(userID)
	if err != nil {
		return info, err
	}
	if target == nil {
		return info, pkgError.ErrUserNotFound
	}

	username, email := target.Username, target.Email
	if request.Username != nil {
		username = *request.Username
		if existing, err := s.storage.GetUserByUsername(username); err != nil {
			return info, err
		} else if existing != nil && existing.ID != userID {
			return info, pkgError.ErrUserAlreadyExists
		}
	}
	if request.Email != nil {
		email = *request.Email
		if existing, err := s.storage.GetUserByEmail(email); err != nil {
			return info, err
		} else if existing != nil && existing.ID != userID {
			return info, pkgError.ErrEmailAlreadyExists
		}
	}
	if username != target.Username || email != target.Email {
		if err := s.storage.UpdateUser(userID, username, email); err != nil {
			return info, err
		}
	}

	if request.IsAdmin != nil && *request.IsAdmin != target.IsAdmin {
		// An admin can never demote themselves: two admins could otherwise
		// demote each other and leave the deployment with no admin at all.
		if !*request.IsAdmin && caller.ID == userID {
			return info, pkgError.ErrCannotDemoteSelf
		}
		if err := s.storage.SetUserAdmin(userID, *request.IsAdmin); err != nil {
			return info, err
		}
	}
	return s.adminInfo(userID)
}

// AdminSetUserPassword resets an account's password and revokes every session
// of that account: the old password must stop working everywhere at once.
func (s *serviceAuth) AdminSetUserPassword(ctx context.Context, userID int64, password string) error {
	if _, err := s.requireAdmin(ctx); err != nil {
		return err
	}
	if err := validations.ValidateAdminPasswordRequest(ctx, domainAuth.AdminPasswordRequest{Password: password}); err != nil {
		return err
	}
	if s.storage == nil {
		return fmt.Errorf("chat storage not initialized")
	}

	target, err := s.storage.GetUserByID(userID)
	if err != nil {
		return err
	}
	if target == nil {
		return pkgError.ErrUserNotFound
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	if err := s.storage.SetUserPassword(userID, string(passwordHash)); err != nil {
		return err
	}
	return s.storage.DeleteUserAuthTokens(userID)
}

// AdminDeleteUser removes an account. Guards: an admin cannot delete their own
// account, and an account that still owns WhatsApp devices must have those
// devices removed first — deleting the row would strand their sessions with no
// owner to manage them.
func (s *serviceAuth) AdminDeleteUser(ctx context.Context, userID int64) error {
	caller, err := s.requireAdmin(ctx)
	if err != nil {
		return err
	}
	if caller.ID == userID {
		return pkgError.ErrCannotDeleteSelf
	}
	if s.storage == nil {
		return fmt.Errorf("chat storage not initialized")
	}

	target, err := s.storage.GetUserByID(userID)
	if err != nil {
		return err
	}
	if target == nil {
		return pkgError.ErrUserNotFound
	}

	deviceCount, err := s.storage.CountUserDevices(userID)
	if err != nil {
		return err
	}
	if deviceCount > 0 {
		return pkgError.ErrUserOwnsDevices
	}

	// auth_tokens has no ON DELETE CASCADE, so revoke first.
	if err := s.storage.DeleteUserAuthTokens(userID); err != nil {
		return err
	}
	return s.storage.DeleteUser(userID)
}

// ChangeOwnPassword rotates the authenticated user's password after proving
// knowledge of the current one. Every Bearer session of that user is revoked:
// the dashboard's Basic credentials are stateless and simply start failing
// until the user signs in with the new password.
func (s *serviceAuth) ChangeOwnPassword(ctx context.Context, request domainAuth.ChangePasswordRequest) error {
	user, ok := domainChatStorage.UserFromContext(ctx)
	if !ok || user == nil {
		return pkgError.ErrUnauthorized
	}
	if err := validations.ValidateChangePasswordRequest(ctx, request); err != nil {
		return err
	}
	if s.storage == nil {
		return fmt.Errorf("chat storage not initialized")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.CurrentPassword)); err != nil {
		return pkgError.ErrCurrentPasswordBad
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	if err := s.storage.SetUserPassword(user.ID, string(passwordHash)); err != nil {
		return err
	}
	return s.storage.DeleteUserAuthTokens(user.ID)
}

// ChangeOwnEmail swaps the authenticated user's email after verifying the
// account password, so a hijacked session cannot silently steal the address.
func (s *serviceAuth) ChangeOwnEmail(ctx context.Context, request domainAuth.ChangeEmailRequest) (domainAuth.UserInfo, error) {
	var info domainAuth.UserInfo
	user, ok := domainChatStorage.UserFromContext(ctx)
	if !ok || user == nil {
		return info, pkgError.ErrUnauthorized
	}
	request.Email = strings.TrimSpace(request.Email)
	if err := validations.ValidateChangeEmailRequest(ctx, request); err != nil {
		return info, err
	}
	if s.storage == nil {
		return info, fmt.Errorf("chat storage not initialized")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.CurrentPassword)); err != nil {
		return info, pkgError.ErrCurrentPasswordBad
	}

	if existing, err := s.storage.GetUserByEmail(request.Email); err != nil {
		return info, err
	} else if existing != nil && existing.ID != user.ID {
		return info, pkgError.ErrEmailAlreadyExists
	}
	if err := s.storage.UpdateUser(user.ID, user.Username, request.Email); err != nil {
		return info, err
	}

	deviceCount, _ := s.storage.CountUserDevices(user.ID)
	return domainAuth.UserInfo{
		ID:          user.ID,
		Username:    user.Username,
		Email:       request.Email,
		DeviceCount: deviceCount,
		IsAdmin:     user.IsAdmin,
	}, nil
}

// adminInfo re-reads an account and renders the admin-facing view of it, so
// every admin mutation returns the same shape as ListUsers.
func (s *serviceAuth) adminInfo(userID int64) (domainAuth.AdminUserInfo, error) {
	user, err := s.storage.GetUserByID(userID)
	if err != nil {
		return domainAuth.AdminUserInfo{}, err
	}
	if user == nil {
		return domainAuth.AdminUserInfo{}, pkgError.ErrUserNotFound
	}
	deviceCount, _ := s.storage.CountUserDevices(user.ID)
	return domainAuth.AdminUserInfo{
		ID:          user.ID,
		Username:    user.Username,
		Email:       user.Email,
		IsAdmin:     user.IsAdmin,
		Disabled:    user.Disabled,
		DeviceCount: deviceCount,
		CreatedAt:   user.CreatedAt,
	}, nil
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

// deriveUsernameFromEmail builds a valid unique username from an email's
// local part: invalid characters are dropped, the result is capped at 32
// chars, and a numeric suffix is appended until it is free.
func (s *serviceAuth) deriveUsernameFromEmail(email string) string {
	at := strings.IndexByte(email, '@')
	local := email
	if at >= 0 {
		local = email[:at]
	}

	// Keep only the characters allowed by the username pattern.
	var b strings.Builder
	for _, r := range local {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	base := strings.Trim(b.String(), "._-")
	if base == "" {
		base = "user"
	}
	if len(base) > 32 {
		base = base[:32]
	}

	// Append a numeric suffix until the name is free.
	candidate := base
	for suffix := 2; ; suffix++ {
		existing, err := s.storage.GetUserByUsername(candidate)
		if err != nil || existing == nil {
			return candidate
		}
		// Leave room for the widest suffix while staying under 32 chars.
		prefix := base
		if len(prefix) > 32-len(strconv.Itoa(suffix)) {
			prefix = prefix[:32-len(strconv.Itoa(suffix))]
		}
		candidate = fmt.Sprintf("%s%d", prefix, suffix)
	}
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