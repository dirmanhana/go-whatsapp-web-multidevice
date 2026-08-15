package validations

import (
	"context"
	"regexp"

	domainAuth "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/auth"
	pkgError "github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/error"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// ValidateRegisterRequest validates a new account registration. Usernames are
// 3-32 chars of letters, digits, dot, underscore or dash; passwords are 6-72
// chars (72 being bcrypt's input ceiling).
func ValidateRegisterRequest(ctx context.Context, request domainAuth.RegisterRequest) error {
	err := validation.ValidateStructWithContext(ctx, &request,
		validation.Field(&request.Username,
			validation.Required,
			validation.Length(3, 32),
			validation.Match(usernamePattern),
		),
		validation.Field(&request.Password,
			validation.Required,
			validation.Length(6, 72),
		),
	)
	if err != nil {
		return pkgError.ValidationError("validate register request: " + err.Error())
	}
	return nil
}

func ValidateLoginRequest(ctx context.Context, request domainAuth.LoginRequest) error {
	err := validation.ValidateStructWithContext(ctx, &request,
		validation.Field(&request.Username, validation.Required),
		validation.Field(&request.Password, validation.Required),
	)
	if err != nil {
		return pkgError.ValidationError("validate login request: " + err.Error())
	}
	return nil
}
