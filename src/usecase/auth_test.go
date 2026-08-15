package usecase

import (
	"context"
	"sort"
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
	createdAt time.Time
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
	s.tokens[tokenHash] = &authToken{userID: userID, expiresAt: expiresAt, createdAt: time.Now()}
	return nil
}

func (s *authRepoStub) ListAuthTokens(userID int64) ([]domainChatStorage.AuthToken, error) {
	tokens := []domainChatStorage.AuthToken{}
	for hash, tok := range s.tokens {
		if tok.userID == userID {
			tokens = append(tokens, domainChatStorage.AuthToken{
				UserID:    tok.userID,
				TokenHash: hash,
				ExpiresAt: tok.expiresAt,
				CreatedAt: tok.createdAt,
			})
		}
	}
	sort.Slice(tokens, func(i, j int) bool {
		if tokens[i].CreatedAt.Equal(tokens[j].CreatedAt) {
			return tokens[i].TokenHash > tokens[j].TokenHash
		}
		return tokens[i].CreatedAt.After(tokens[j].CreatedAt)
	})
	return tokens, nil
}

func (s *authRepoStub) DeleteUserAuthTokens(userID int64) error {
	for hash, tok := range s.tokens {
		if tok.userID == userID {
			delete(s.tokens, hash)
		}
	}
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

func TestAuthSessionsAndLogoutAll(t *testing.T) {
	saveAuthConfig()
	repo := newAuthRepoStub()
	svc := NewAuthService(repo)
	ctx := domainChatStorage.ContextWithUser(context.Background(), &domainChatStorage.User{ID: 7, Username: "carol"})

	// No user in context -> unauthorized.
	_, err := svc.Sessions(context.Background())
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)
	require.ErrorIs(t, svc.LogoutAll(context.Background()), pkgError.ErrUnauthorized)

	// Seed one live and one expired session directly, with deterministic
	// created_at so the newest-first ordering is stable.
	require.NoError(t, repo.CreateAuthToken(hashAuthToken("live-token"), 7, time.Now().Add(time.Hour)))
	require.NoError(t, repo.CreateAuthToken(hashAuthToken("dead-token"), 7, time.Now().Add(-time.Minute)))
	now := time.Now()
	repo.tokens[hashAuthToken("live-token")].createdAt = now
	repo.tokens[hashAuthToken("dead-token")].createdAt = now.Add(-time.Minute)

	sessions, err := svc.Sessions(ctx)
	require.NoError(t, err)
	require.Len(t, sessions, 2)
	for _, session := range sessions {
		assert.Equal(t, 8, len(session.TokenID)-3, "token id must be masked: %q", session.TokenID)
		assert.False(t, session.ExpiresAt.IsZero())
		assert.False(t, session.CreatedAt.IsZero())
	}
	// The expired session is flagged; live one is not. Ordering is newest
	// first, so the live session comes before the expired one.
	assert.False(t, sessions[0].Expired)
	assert.True(t, sessions[1].Expired)

	// The masked id must not match the full digest.
	for _, session := range sessions {
		assert.NotEqual(t, hashAuthToken("live-token"), session.TokenID)
		assert.NotEqual(t, hashAuthToken("dead-token"), session.TokenID)
	}

	// LogoutAll revokes every session of the user.
	require.NoError(t, svc.LogoutAll(ctx))
	sessions, err = svc.Sessions(ctx)
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestMaskAuthTokenHash(t *testing.T) {
	assert.Equal(t, "cafebabe...", maskAuthTokenHash("cafebabe1234567890"))
	assert.Equal(t, "short", maskAuthTokenHash("short"))
	assert.Equal(t, "", maskAuthTokenHash(""))
}