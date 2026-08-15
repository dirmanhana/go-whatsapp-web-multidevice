package validations

import (
	"context"
	"testing"

	domainAuth "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/auth"
	"github.com/stretchr/testify/assert"
)

func TestValidateRegisterRequest(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		wantErr  bool
	}{
		{name: "valid", username: "alice", password: "secret123", wantErr: false},
		{name: "valid with dot/underscore/dash", username: "a.lice_w-1", password: "secret123", wantErr: false},
		{name: "empty username", username: "", password: "secret123", wantErr: true},
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