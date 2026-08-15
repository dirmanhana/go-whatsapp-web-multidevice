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

	id, err := s.storage.CreateUser(username, string(passwordHash))
	if err != nil {
		return info, err
	}

	return domainAuth.UserInfo{ID: id, Username: username, DeviceCount: 0}, nil
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
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(request.Password)); err != nil {
		return response, pkgError.ErrInvalidCredentials
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
	if user == nil {
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
	}, nil
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