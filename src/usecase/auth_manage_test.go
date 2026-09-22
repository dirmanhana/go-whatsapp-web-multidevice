package usecase

import (
	"context"
	"testing"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	domainAuth "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/auth"
	domainChatStorage "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/chatstorage"
	pkgError "github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/error"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// newManagedFixture boots a service holding two accounts: an admin (the first
// registered user, per bootstrap rules) and a regular user. It returns the
// service, its repository, and both request contexts — each already carrying
// the full stored user (password hash included, exactly as AuthMiddleware
// attaches them).
func newManagedFixture(t *testing.T) (domainAuth.IAuthUsecase, *authRepoStub, context.Context, context.Context, domainAuth.UserInfo, domainAuth.UserInfo) {
	t.Helper()
	saveAuthConfig()
	prevAdmin := config.AuthAdminUsername
	config.AuthAdminUsername = ""
	t.Cleanup(func() { config.AuthAdminUsername = prevAdmin })

	repo := newAuthRepoStub()
	svc := NewAuthService(repo)

	adminInfo, err := svc.Register(context.Background(), domainAuth.RegisterRequest{Username: "boss", Password: "secret123"})
	require.NoError(t, err)
	require.True(t, adminInfo.IsAdmin)

	plainInfo, err := svc.Register(context.Background(), domainAuth.RegisterRequest{Username: "staff", Password: "secret123"})
	require.NoError(t, err)
	require.False(t, plainInfo.IsAdmin)

	adminUser, err := repo.GetUserByUsername("boss")
	require.NoError(t, err)
	require.NotNil(t, adminUser)
	plainUser, err := repo.GetUserByUsername("staff")
	require.NoError(t, err)
	require.NotNil(t, plainUser)

	adminCtx := domainChatStorage.ContextWithUser(context.Background(), adminUser)
	plainCtx := domainChatStorage.ContextWithUser(context.Background(), plainUser)
	return svc, repo, adminCtx, plainCtx, adminInfo, plainInfo
}

func strPtr(value string) *string { return &value }
func boolPtr(value bool) *bool    { return &value }

func TestAdminCreateUser(t *testing.T) {
	svc, repo, adminCtx, plainCtx, _, _ := newManagedFixture(t)

	// Admin provisions an account by email alone; the username is derived.
	created, err := svc.AdminCreateUser(adminCtx, domainAuth.AdminCreateUserRequest{
		Email:    "dirmanhana@gmail.com",
		Password: "Rifdahana290112#",
		IsAdmin:  true,
	})
	require.NoError(t, err)
	assert.Equal(t, "dirmanhana", created.Username, "username must be derived from the email local part")
	assert.Equal(t, "dirmanhana@gmail.com", created.Email)
	assert.True(t, created.IsAdmin)
	assert.False(t, created.Disabled)
	assert.False(t, created.CreatedAt.IsZero())
	assert.Zero(t, created.DeviceCount)

	// The new account signs in with its email and carries the admin flag.
	resp, err := svc.Login(context.Background(), domainAuth.LoginRequest{
		Username: "dirmanhana@gmail.com",
		Password: "Rifdahana290112#",
	})
	require.NoError(t, err)
	assert.True(t, resp.User.IsAdmin)
	assert.Equal(t, "dirmanhana", resp.User.Username)

	// Conflicts are rejected case-insensitively, as registration does.
	_, err = svc.AdminCreateUser(adminCtx, domainAuth.AdminCreateUserRequest{
		Email:    "DIRMANHANA@GMAIL.COM",
		Password: "secret123",
	})
	require.ErrorIs(t, err, pkgError.ErrEmailAlreadyExists)

	_, err = svc.AdminCreateUser(adminCtx, domainAuth.AdminCreateUserRequest{
		Username: "taken.name",
		Email:    "other@example.com",
		Password: "secret123",
	})
	require.NoError(t, err)
	_, err = svc.AdminCreateUser(adminCtx, domainAuth.AdminCreateUserRequest{
		Username: "taken.name",
		Email:    "third@example.com",
		Password: "secret123",
	})
	require.ErrorIs(t, err, pkgError.ErrUserAlreadyExists)

	// Validation runs before any storage work.
	_, err = svc.AdminCreateUser(adminCtx, domainAuth.AdminCreateUserRequest{Password: "secret123"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate admin create user request")

	_, err = svc.AdminCreateUser(adminCtx, domainAuth.AdminCreateUserRequest{
		Username: "shorty",
		Password: "12345",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate admin create user request")

	// Only admins may provision accounts: a plain user gets 403, an anonymous
	// caller (no user in context) gets 401.
	_, err = svc.AdminCreateUser(plainCtx, domainAuth.AdminCreateUserRequest{
		Username: "sneaky",
		Password: "secret123",
	})
	require.ErrorIs(t, err, pkgError.ErrForbidden)
	_, err = svc.AdminCreateUser(context.Background(), domainAuth.AdminCreateUserRequest{
		Username: "anon",
		Password: "secret123",
	})
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)

	// The account really landed in storage.
	stored, err := repo.GetUserByEmail("dirmanhana@gmail.com")
	require.NoError(t, err)
	require.NotNil(t, stored)
}

func TestAdminUpdateUser(t *testing.T) {
	svc, repo, adminCtx, plainCtx, adminInfo, plainInfo := newManagedFixture(t)

	// Only admins may edit: this runs while the target is still a plain user.
	_, err := svc.AdminUpdateUser(plainCtx, adminInfo.ID, domainAuth.AdminUpdateUserRequest{Username: strPtr("hijacked")})
	require.ErrorIs(t, err, pkgError.ErrForbidden)

	// Rename the regular user and give them an email.
	updated, err := svc.AdminUpdateUser(adminCtx, plainInfo.ID, domainAuth.AdminUpdateUserRequest{
		Username: strPtr("staff.renamed"),
		Email:    strPtr("staff@example.com"),
	})
	require.NoError(t, err)
	assert.Equal(t, "staff.renamed", updated.Username)
	assert.Equal(t, "staff@example.com", updated.Email)

	// The renamed account signs in under its new identifiers; the old one is gone.
	_, err = svc.Login(context.Background(), domainAuth.LoginRequest{Username: "staff.renamed", Password: "secret123"})
	require.NoError(t, err)
	_, err = svc.Login(context.Background(), domainAuth.LoginRequest{Username: "staff", Password: "secret123"})
	require.ErrorIs(t, err, pkgError.ErrInvalidCredentials)

	// An edit naming no field at all, or an ill-formed one, is a validation error.
	_, err = svc.AdminUpdateUser(adminCtx, plainInfo.ID, domainAuth.AdminUpdateUserRequest{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate admin update user request")
	_, err = svc.AdminUpdateUser(adminCtx, plainInfo.ID, domainAuth.AdminUpdateUserRequest{Email: strPtr("not-an-email")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate admin update user request")

	// Renaming onto another account's email is a conflict.
	_, err = svc.AdminUpdateUser(adminCtx, adminInfo.ID, domainAuth.AdminUpdateUserRequest{Email: strPtr("staff@example.com")})
	require.ErrorIs(t, err, pkgError.ErrEmailAlreadyExists)

	// Promote a user to admin.
	promoted, err := svc.AdminUpdateUser(adminCtx, plainInfo.ID, domainAuth.AdminUpdateUserRequest{IsAdmin: boolPtr(true)})
	require.NoError(t, err)
	assert.True(t, promoted.IsAdmin)
	stored, err := repo.GetUserByID(plainInfo.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.True(t, stored.IsAdmin)

	// An admin cannot remove their own admin flag: the deployment must never
	// end up with zero admins.
	_, err = svc.AdminUpdateUser(adminCtx, adminInfo.ID, domainAuth.AdminUpdateUserRequest{IsAdmin: boolPtr(false)})
	require.ErrorIs(t, err, pkgError.ErrCannotDemoteSelf)

	// Unknown accounts fail cleanly.
	_, err = svc.AdminUpdateUser(adminCtx, 9999, domainAuth.AdminUpdateUserRequest{Username: strPtr("ghost")})
	require.ErrorIs(t, err, pkgError.ErrUserNotFound)
}

func TestAdminSetUserPassword(t *testing.T) {
	svc, repo, adminCtx, plainCtx, adminInfo, plainInfo := newManagedFixture(t)

	// The target signs in, holding a session that must die on reset.
	victim, err := svc.Login(context.Background(), domainAuth.LoginRequest{Username: "staff", Password: "secret123"})
	require.NoError(t, err)

	require.NoError(t, svc.AdminSetUserPassword(adminCtx, plainInfo.ID, "BrandNewPass1!"))

	// Old password no longer works; the new one does.
	_, err = svc.Login(context.Background(), domainAuth.LoginRequest{Username: "staff", Password: "secret123"})
	require.ErrorIs(t, err, pkgError.ErrInvalidCredentials)
	_, err = svc.Login(context.Background(), domainAuth.LoginRequest{Username: "staff", Password: "BrandNewPass1!"})
	require.NoError(t, err)

	// The session opened before the reset is revoked.
	_, err = svc.Authenticate(context.Background(), victim.Token)
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)

	// Only a bcrypt digest of the new password is stored.
	stored, err := repo.GetUserByID(plainInfo.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.NotEqual(t, "BrandNewPass1!", stored.PasswordHash)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored.PasswordHash), []byte("BrandNewPass1!")))

	// Guards: bad payload, unknown account, non-admin caller.
	require.Error(t, svc.AdminSetUserPassword(adminCtx, plainInfo.ID, "12345"))
	require.ErrorIs(t, svc.AdminSetUserPassword(adminCtx, 9999, "BrandNewPass1!"), pkgError.ErrUserNotFound)
	require.ErrorIs(t, svc.AdminSetUserPassword(plainCtx, adminInfo.ID, "BrandNewPass1!"), pkgError.ErrForbidden)
}

func TestAdminDeleteUser(t *testing.T) {
	svc, repo, adminCtx, plainCtx, adminInfo, plainInfo := newManagedFixture(t)

	// A device owned by the account blocks deletion: orphaning a linked
	// WhatsApp session must be a deliberate act, not a click.
	repo.deviceOwners["device-1"] = plainInfo.ID
	require.ErrorIs(t, svc.AdminDeleteUser(adminCtx, plainInfo.ID), pkgError.ErrUserOwnsDevices)

	// Once the device is gone, the account can be removed.
	delete(repo.deviceOwners, "device-1")
	victim, err := svc.Login(context.Background(), domainAuth.LoginRequest{Username: "staff", Password: "secret123"})
	require.NoError(t, err)

	require.NoError(t, svc.AdminDeleteUser(adminCtx, plainInfo.ID))

	gone, err := repo.GetUserByID(plainInfo.ID)
	require.NoError(t, err)
	assert.Nil(t, gone)
	_, err = svc.Login(context.Background(), domainAuth.LoginRequest{Username: "staff", Password: "secret123"})
	require.ErrorIs(t, err, pkgError.ErrInvalidCredentials)
	// Its sessions died with it.
	_, err = svc.Authenticate(context.Background(), victim.Token)
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)

	// Self-deletion, unknown accounts, and non-admin callers are all refused.
	require.ErrorIs(t, svc.AdminDeleteUser(adminCtx, adminInfo.ID), pkgError.ErrCannotDeleteSelf)
	require.ErrorIs(t, svc.AdminDeleteUser(adminCtx, 9999), pkgError.ErrUserNotFound)
	require.ErrorIs(t, svc.AdminDeleteUser(plainCtx, adminInfo.ID), pkgError.ErrForbidden)
}

func TestChangeOwnPassword(t *testing.T) {
	svc, repo, _, plainCtx, _, plainInfo := newManagedFixture(t)

	// Without an authenticated user in context nothing happens.
	require.ErrorIs(t, svc.ChangeOwnPassword(context.Background(), domainAuth.ChangePasswordRequest{
		CurrentPassword: "secret123",
		Password:        "whatever123",
	}), pkgError.ErrUnauthorized)

	// The wrong current password is refused before anything is written.
	require.ErrorIs(t, svc.ChangeOwnPassword(plainCtx, domainAuth.ChangePasswordRequest{
		CurrentPassword: "wrong",
		Password:        "whatever123",
	}), pkgError.ErrCurrentPasswordBad)

	// A too-short replacement is a validation error, reported as such.
	err := svc.ChangeOwnPassword(plainCtx, domainAuth.ChangePasswordRequest{
		CurrentPassword: "secret123",
		Password:        "12345",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate change password request")

	// Sign in to hold a session across the change.
	before, err := svc.Login(context.Background(), domainAuth.LoginRequest{Username: "staff", Password: "secret123"})
	require.NoError(t, err)

	require.NoError(t, svc.ChangeOwnPassword(plainCtx, domainAuth.ChangePasswordRequest{
		CurrentPassword: "secret123",
		Password:        "RotatedPass42#",
	}))

	// Old password dead, new password live.
	_, err = svc.Login(context.Background(), domainAuth.LoginRequest{Username: "staff", Password: "secret123"})
	require.ErrorIs(t, err, pkgError.ErrInvalidCredentials)
	_, err = svc.Login(context.Background(), domainAuth.LoginRequest{Username: "staff", Password: "RotatedPass42#"})
	require.NoError(t, err)

	// Existing sessions are revoked together with the change.
	_, err = svc.Authenticate(context.Background(), before.Token)
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)

	stored, err := repo.GetUserByID(plainInfo.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(stored.PasswordHash), []byte("RotatedPass42#")))

	// Other accounts keep their own credentials.
	_, err = svc.Login(context.Background(), domainAuth.LoginRequest{Username: "boss", Password: "secret123"})
	require.NoError(t, err)
}

func TestChangeOwnEmail(t *testing.T) {
	svc, repo, adminCtx, plainCtx, adminInfo, plainInfo := newManagedFixture(t)

	// Without a user in context: unauthorized.
	_, err := svc.ChangeOwnEmail(context.Background(), domainAuth.ChangeEmailRequest{
		CurrentPassword: "secret123",
		Email:           "someone@example.com",
	})
	require.ErrorIs(t, err, pkgError.ErrUnauthorized)

	// Confirmation password is mandatory and must match.
	_, err = svc.ChangeOwnEmail(plainCtx, domainAuth.ChangeEmailRequest{CurrentPassword: "wrong", Email: "new@example.com"})
	require.ErrorIs(t, err, pkgError.ErrCurrentPasswordBad)

	// Malformed addresses are rejected by validation.
	_, err = svc.ChangeOwnEmail(plainCtx, domainAuth.ChangeEmailRequest{CurrentPassword: "secret123", Email: "nope"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validate change email request")

	// Take an address for the admin, then try to claim it as staff.
	_, err = svc.AdminUpdateUser(adminCtx, adminInfo.ID, domainAuth.AdminUpdateUserRequest{Email: strPtr("boss@example.com")})
	require.NoError(t, err)
	_, err = svc.ChangeOwnEmail(plainCtx, domainAuth.ChangeEmailRequest{
		CurrentPassword: "secret123",
		Email:           "BOSS@example.com",
	})
	require.ErrorIs(t, err, pkgError.ErrEmailAlreadyExists)

	// The happy path swaps the address (stored trimmed) and keeps the username.
	info, err := svc.ChangeOwnEmail(plainCtx, domainAuth.ChangeEmailRequest{
		CurrentPassword: "secret123",
		Email:           "  staff@example.com  ",
	})
	require.NoError(t, err)
	assert.Equal(t, "staff@example.com", info.Email)
	assert.Equal(t, plainInfo.Username, info.Username)

	// Login accepts the new email as identifier; the stored row matches.
	_, err = svc.Login(context.Background(), domainAuth.LoginRequest{Username: "staff@example.com", Password: "secret123"})
	require.NoError(t, err)

	stored, err := repo.GetUserByID(plainInfo.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "staff@example.com", stored.Email)
	assert.Equal(t, plainInfo.Username, stored.Username, "the username must not follow an email change")
}
