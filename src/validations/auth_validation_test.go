package validations

import (
	"context"
	"testing"

	domainAuth "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRegisterRequest(t *testing.T) {
	tests := []struct {
		name     string
		username string
		email    string
		password string
		wantErr  bool
	}{
		{name: "valid username", username: "alice", password: "secret123", wantErr: false},
		{name: "valid with dot/underscore/dash", username: "a.lice_w-1", password: "secret123", wantErr: false},
		{name: "valid email only", email: "alice@example.com", password: "secret123", wantErr: false},
		{name: "valid email with plus", email: "alice+tag@example.co.id", password: "secret123", wantErr: false},
		{name: "empty username and email", username: "", password: "secret123", wantErr: true},
		{name: "empty email only", email: "", password: "secret123", wantErr: true},
		{name: "malformed email", email: "not-an-email", password: "secret123", wantErr: true},
		{name: "email without tld", email: "alice@localhost", password: "secret123", wantErr: true},
		{name: "too short username", username: "ab", password: "secret123", wantErr: true},
		{name: "too long username", username: "abcdefghijklmnopqrstuvwxyz1234567890", password: "secret123", wantErr: true},
		{name: "username with forbidden chars", username: "ali ce@", password: "secret123", wantErr: true},
		{name: "username with spaces", username: "ali ce", password: "secret123", wantErr: true},
		{name: "empty password", username: "alice", password: "", wantErr: true},
		{name: "too short password", username: "alice", password: "12345", wantErr: true},
		{name: "too long password", username: "alice", password: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRegisterRequest(context.Background(), domainAuth.RegisterRequest{
				Username: tt.username,
				Email:    tt.email,
				Password: tt.password,
			})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateLoginRequest(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{name: "valid", username: "alice", password: "secret123", wantErr: false},
		{name: "empty username", username: "", password: "secret123", wantErr: true},
		{name: "empty password", username: "alice", password: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLoginRequest(context.Background(), domainAuth.LoginRequest{
				Username: tt.username,
				Password: tt.password,
			})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
func TestValidateAdminCreateUserRequest(t *testing.T) {
	tests := []struct {
		name    string
		request domainAuth.AdminCreateUserRequest
		wantErr bool
	}{
		{name: "email only", request: domainAuth.AdminCreateUserRequest{Email: "a@b.com", Password: "secret123"}},
		{name: "username and email", request: domainAuth.AdminCreateUserRequest{Username: "alice", Email: "a@b.com", Password: "secret123"}},
		{name: "admin flag is not validated", request: domainAuth.AdminCreateUserRequest{Username: "alice", Password: "secret123", IsAdmin: true}},
		{name: "no identifier", request: domainAuth.AdminCreateUserRequest{Password: "secret123"}, wantErr: true},
		{name: "invalid email", request: domainAuth.AdminCreateUserRequest{Email: "nope", Password: "secret123"}, wantErr: true},
		{name: "invalid username", request: domainAuth.AdminCreateUserRequest{Username: "a b", Password: "secret123"}, wantErr: true},
		{name: "short password", request: domainAuth.AdminCreateUserRequest{Username: "alice", Password: "12345"}, wantErr: true},
		{name: "missing password", request: domainAuth.AdminCreateUserRequest{Username: "alice"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdminCreateUserRequest(context.Background(), tt.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func strPtr(value string) *string { return &value }
func boolPtr(value bool) *bool    { return &value }

func TestValidateAdminUpdateUserRequest(t *testing.T) {
	tests := []struct {
		name    string
		request domainAuth.AdminUpdateUserRequest
		wantErr bool
	}{
		{name: "username only", request: domainAuth.AdminUpdateUserRequest{Username: strPtr("alice")}},
		{name: "email only", request: domainAuth.AdminUpdateUserRequest{Email: strPtr("a@b.com")}},
		{name: "admin flag only", request: domainAuth.AdminUpdateUserRequest{IsAdmin: boolPtr(true)}},
		{name: "everything at once", request: domainAuth.AdminUpdateUserRequest{Username: strPtr("alice"), Email: strPtr("a@b.com"), IsAdmin: boolPtr(false)}},
		{name: "nothing named", request: domainAuth.AdminUpdateUserRequest{}, wantErr: true},
		{name: "empty username", request: domainAuth.AdminUpdateUserRequest{Username: strPtr("")}, wantErr: true},
		{name: "username too short", request: domainAuth.AdminUpdateUserRequest{Username: strPtr("ab")}, wantErr: true},
		{name: "username with space", request: domainAuth.AdminUpdateUserRequest{Username: strPtr("a lice")}, wantErr: true},
		{name: "empty email", request: domainAuth.AdminUpdateUserRequest{Email: strPtr("")}, wantErr: true},
		{name: "malformed email", request: domainAuth.AdminUpdateUserRequest{Email: strPtr("nope")}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdminUpdateUserRequest(context.Background(), tt.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAdminUpdateUserRequestTrimsInPlace(t *testing.T) {
	request := domainAuth.AdminUpdateUserRequest{
		Username: strPtr("  alice  "),
		Email:    strPtr("  a@b.com  "),
	}
	require.NoError(t, ValidateAdminUpdateUserRequest(context.Background(), request))
	assert.Equal(t, "alice", *request.Username)
	assert.Equal(t, "a@b.com", *request.Email)
}

func TestValidateAdminPasswordRequest(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{name: "valid", password: "secret123"},
		{name: "exactly six chars", password: "123456"},
		{name: "empty", password: "", wantErr: true},
		{name: "too short", password: "12345", wantErr: true},
		{name: "too long", password: "12345678901234567890123456789012345678901234567890123456789012345678901234567890", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAdminPasswordRequest(context.Background(), domainAuth.AdminPasswordRequest{Password: tt.password})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateChangePasswordRequest(t *testing.T) {
	tests := []struct {
		name    string
		request domainAuth.ChangePasswordRequest
		wantErr bool
	}{
		{name: "valid", request: domainAuth.ChangePasswordRequest{CurrentPassword: "old-secret", Password: "new-secret1"}},
		{name: "missing current password", request: domainAuth.ChangePasswordRequest{Password: "new-secret1"}, wantErr: true},
		{name: "missing new password", request: domainAuth.ChangePasswordRequest{CurrentPassword: "old-secret"}, wantErr: true},
		{name: "new password too short", request: domainAuth.ChangePasswordRequest{CurrentPassword: "old-secret", Password: "12345"}, wantErr: true},
		{name: "spaces are kept in the current password", request: domainAuth.ChangePasswordRequest{CurrentPassword: "old secret", Password: "new-secret1"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateChangePasswordRequest(context.Background(), tt.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateChangeEmailRequest(t *testing.T) {
	tests := []struct {
		name    string
		request domainAuth.ChangeEmailRequest
		wantErr bool
	}{
		{name: "valid", request: domainAuth.ChangeEmailRequest{CurrentPassword: "secret123", Email: "me@example.com"}},
		{name: "missing current password", request: domainAuth.ChangeEmailRequest{Email: "me@example.com"}, wantErr: true},
		{name: "missing email", request: domainAuth.ChangeEmailRequest{CurrentPassword: "secret123"}, wantErr: true},
		{name: "malformed email", request: domainAuth.ChangeEmailRequest{CurrentPassword: "secret123", Email: "nope"}, wantErr: true},
		{name: "email without tld", request: domainAuth.ChangeEmailRequest{CurrentPassword: "secret123", Email: "me@localhost"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateChangeEmailRequest(context.Background(), tt.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
