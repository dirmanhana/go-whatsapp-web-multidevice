package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	domainAuth "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/auth"
	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
	pkgError "github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/error"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// authRepoStub is an in-memory chatstorage stub covering only the auth path.
type authRepoStub struct {
	domainChatStorage.IChatStorageRepository
	users        map[string]*domainChatStorage.User
	tokens       map[string]*authToken
	deviceOwners map[string]int64
	nextUserID   int64
}

type authToken struct {
	userID    int64
	expiresAt time.Time
}

func newAuthRepoStub() *authRepoStub {
	return &authRepoStub{
		users:        map[string]*domainChatStorage.User{},
		tokens:       map[string]*authToken{},
		deviceOwners: map[string]int64{},
		nextUserID:   1,
	}
}

func (s *authRepoStub) CreateUser(username, passwordHash string) (int64, error) {
	for _, u := range s.users {
		if u.Username == username {
			return 0, pkgError.ErrUserAlreadyExists
		}
	}
	id := s.nextUserID
	s.nextUserID++
	s.users[username] = &domainChatStorage.User{ID: id, Username: username, PasswordHash: passwordHash, CreatedAt: time.Now()}
	return id, nil
}

func (s *authRepoStub) GetUserByUsername(username string) (*domainChatStorage.User, error) {
	if u, ok := s.users[username]; ok {
		return u, nil
	}
	return nil, nil
}

func (s *authRepoStub) GetUserByID(id int64) (*domainChatStorage.User, error) {
	for _, u := range s.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, nil
}

func (s *authRepoStub) GetUserByTokenHash(tokenHash string) (*domainChatStorage.User, error) {
	tok, ok := s.tokens[tokenHash]
	if !ok || time.Now().After(tok.expiresAt) {
		return nil, nil
	}
	return s.GetUserByID(tok.userID)
}

func (s *authRepoStub) CreateAuthToken(tokenHash string, userID int64, expiresAt time.Time) error {
	s.tokens[tokenHash] = &authToken{userID: userID, expiresAt: expiresAt}
	return nil
}

func (s *authRepoStub) DeleteAuthToken(tokenHash string) error {
	delete(s.tokens, tokenHash)
	return nil
}

func (s *authRepoStub) DeleteExpiredAuthTokens() error {
	for hash, tok := range s.tokens {
		if time.Now().After(tok.expiresAt) {
			delete(s.tokens, hash)
		}
	}
	return nil
}

func (s *authRepoStub) CountUserDevices(userID int64) (int, error) {
	count := 0
	for _, owner := range s.deviceOwners {
		if owner == userID {
			count++
		}
	}
	return count, nil
}

func saveAuthConfig() {
	// Ensure defaults are applied (config globals may have been mutated).
	if config.AuthTokenTTL <= 0 {
		config.AuthTokenTTL = 24 * time.Hour
	}
}

func TestAuthRegisterLoginLogout(t *testing.T) {
	saveAuthConfig()
	svc := NewAuthService(newAuthRepoStub())

	// Register
	info, err := svc.Register(context.Background(), domainAuth.RegisterRequest{Username: "alice", Password: "secret123"})
	require.NoError(t, err)
	assert.NotZero(t, info.ID)
	assert.Equal(t, "alice", info.Username)
	assert.Equal(t, 0, info.DeviceCount)

	// Duplicate register
	_, err = svc.Register(context.Background(), domainAuth.RegisterRequest{Username: "alice", Password: "secret123"})
	require.ErrorIs(t, err, pkgError.ErrUserAlreadyExists)

	// Login with wrong password
	_, err = svc.Login(context.Background(), domainAuth.LoginRequest{Username: "alice", Password: "wrong"})
	require.ErrorIs(t, err, pkgError.ErrInvalidCredentials)

	// Login with unknown user
	_, err = svc.Login(context.Background(), domainAuth.LoginRequest{Username: "nobody", Password: "secret123"})
	require.ErrorIs(t, err, pkgError.ErrInvalidCredentials)

	// Valid login issues a token
	resp, err := svc.Login(context.Background(), domainAuth.LoginRequest{Username: "alice", Password: "secret123"})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
	assert.False(t, resp.ExpiresAt.IsZero())
	assert.Equal(t, "alice", resp.User.Username)

	// Token authenticates
	user, err := svc.Authenticate(context.Background(), resp.Token)
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "alice", user.Username)

	// Logout revokes the token
	require.NoError(t, svc.Logout(context.Background(), resp.Token))
	user, err = svc.Authenticate(context.Background(), resp.Token)
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)
	assert.Nil(t, user)
}

func TestAuthAuthenticateRejectsBadToken(t *testing.T) {
	svc := NewAuthService(newAuthRepoStub())
	_, err := svc.Authenticate(context.Background(), "")
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)
	_, err = svc.Authenticate(context.Background(), "garbage-token")
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)
}

func TestAuthPasswordHashed(t *testing.T) {
	saveAuthConfig()
	repo := newAuthRepoStub()
	svc := NewAuthService(repo)

	_, err := svc.Register(context.Background(), domainAuth.RegisterRequest{Username: "bob", Password: "secret123"})
	require.NoError(t, err)

	stored, err := repo.GetUserByUsername("bob")
	require.NoError(t, err)
	require.NotNil(t, stored)
	// The plaintext password must never be stored.
	assert.NotEqual(t, "secret123", stored.PasswordHash)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored.PasswordHash), []byte("secret123")))
}

func TestAuthAuthenticateBasic(t *testing.T) {
	saveAuthConfig()
	svc := NewAuthService(newAuthRepoStub())

	_, err := svc.Register(context.Background(), domainAuth.RegisterRequest{Username: "bob", Password: "secret123"})
	require.NoError(t, err)

	user, err := svc.AuthenticateBasic(context.Background(), "bob", "secret123")
	require.NoError(t, err)
	require.NotNil(t, user)
	assert.Equal(t, "bob", user.Username)

	// Wrong password / unknown user / empty inputs all fail with the same error.
	_, err = svc.AuthenticateBasic(context.Background(), "bob", "wrong")
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)
	_, err = svc.AuthenticateBasic(context.Background(), "nobody", "secret123")
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)
	_, err = svc.AuthenticateBasic(context.Background(), "", "")
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)
}

func TestAuthMeRequiresUserInContext(t *testing.T) {
	saveAuthConfig()
	svc := NewAuthService(newAuthRepoStub())

	_, err := svc.Me(context.Background())
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)

	ctx := domainChatStorage.ContextWithUser(context.Background(), &domainChatStorage.User{ID: 7, Username: "carol"})
	info, err := svc.Me(ctx)
	require.NoError(t, err)
	assert.Equal(t, "carol", info.Username)
}