package validations

import (
	"context"
	"regexp"
	"strings"

	domainAuth "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/auth"
	pkgError "github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/error"
	validation "github.com/go-ozzo/ozzo-validation/v4"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

var emailPattern = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// ValidateRegisterRequest validates a new account registration. Self-service
// registration needs Email + Password; the username is optional and derived
// from the email when absent. Legacy clients may still send Username +
// Password with an empty email. Usernames are 3-32 chars of letters, digits,
// dot, underscore or dash; passwords are 6-72 chars (72 being bcrypt's input
// ceiling).
func ValidateRegisterRequest(ctx context.Context, request domainAuth.RegisterRequest) error {
	return validateAccountShape(ctx, "validate register request", request.Username, request.Email, request.Password)
}

// accountShape is the shared username/email/password triple behind both
// self-service registration and admin-provisioned accounts.
type accountShape struct {
	Username string
	Email    string
	Password string
}

// validateAccountShape enforces the account rules shared by registration and
// admin creation: at least one of username/email, and a 6-72 char password.
func validateAccountShape(ctx context.Context, label, username, email, password string) error {
	shape := accountShape{Username: username, Email: email, Password: password}
	usernameGiven := strings.TrimSpace(shape.Username) != ""
	emailGiven := strings.TrimSpace(shape.Email) != ""
	if !usernameGiven && !emailGiven {
		return pkgError.ValidationError(label + ": either username or email is required")
	}

	err := validation.ValidateStructWithContext(ctx, &shape,
		validation.Field(&shape.Username,
			validation.When(usernameGiven,
				validation.Length(3, 32),
				validation.Match(usernamePattern),
			),
		),
		validation.Field(&shape.Email,
			validation.When(emailGiven,
				validation.Length(3, 255),
				validation.Match(emailPattern),
			),
		),
		validation.Field(&shape.Password,
			validation.Required,
			validation.Length(6, 72),
		),
	)
	if err != nil {
		return pkgError.ValidationError(label + ": " + err.Error())
	}
	return nil
}

// ValidateAdminCreateUserRequest validates an account an admin provisions for
// someone else. Same shape as registration; deriving the username from the
// email belongs to the usecase.
func ValidateAdminCreateUserRequest(ctx context.Context, request domainAuth.AdminCreateUserRequest) error {
	return validateAccountShape(ctx, "validate admin create user request", request.Username, request.Email, request.Password)
}

// ValidateAdminUpdateUserRequest validates a partial account edit: at least
// one field must be named, and the provided username/email must be
// well-formed. Values are trimmed in place before validation, so callers store
// exactly what was checked. Clearing the email is not supported (send the
// current address instead).
func ValidateAdminUpdateUserRequest(ctx context.Context, request domainAuth.AdminUpdateUserRequest) error {
	if request.Username == nil && request.Email == nil && request.IsAdmin == nil {
		return pkgError.ValidationError("validate admin update user request: at least one of username, email, is_admin is required")
	}
	if request.Username != nil {
		trimmed := strings.TrimSpace(*request.Username)
		*request.Username = trimmed
	}
	if request.Email != nil {
		trimmed := strings.TrimSpace(*request.Email)
		*request.Email = trimmed
	}

	err := validation.ValidateStructWithContext(ctx, &request,
		validation.Field(&request.Username,
			validation.When(request.Username != nil,
				validation.Required,
				validation.Length(3, 32),
				validation.Match(usernamePattern),
			),
		),
		validation.Field(&request.Email,
			validation.When(request.Email != nil,
				validation.Required,
				validation.Length(3, 255),
				validation.Match(emailPattern),
			),
		),
	)
	if err != nil {
		return pkgError.ValidationError("validate admin update user request: " + err.Error())
	}
	return nil
}

// ValidateAdminPasswordRequest validates an admin password reset: the new
// password only, 6-72 chars.
func ValidateAdminPasswordRequest(ctx context.Context, request domainAuth.AdminPasswordRequest) error {
	err := validation.ValidateStructWithContext(ctx, &request,
		validation.Field(&request.Password, validation.Required, validation.Length(6, 72)),
	)
	if err != nil {
		return pkgError.ValidationError("validate admin password request: " + err.Error())
	}
	return nil
}

// ValidateChangePasswordRequest validates a self-service password rotation.
// The current password is mandatory so a hijacked session cannot lock the
// owner out of their own account.
func ValidateChangePasswordRequest(ctx context.Context, request domainAuth.ChangePasswordRequest) error {
	err := validation.ValidateStructWithContext(ctx, &request,
		validation.Field(&request.CurrentPassword, validation.Required),
		validation.Field(&request.Password, validation.Required, validation.Length(6, 72)),
	)
	if err != nil {
		return pkgError.ValidationError("validate change password request: " + err.Error())
	}
	return nil
}

// ValidateChangeEmailRequest validates a self-service email change, confirmed
// with the account password.
func ValidateChangeEmailRequest(ctx context.Context, request domainAuth.ChangeEmailRequest) error {
	err := validation.ValidateStructWithContext(ctx, &request,
		validation.Field(&request.CurrentPassword, validation.Required),
		validation.Field(&request.Email,
			validation.Required,
			validation.Length(3, 255),
			validation.Match(emailPattern),
		),
	)
	if err != nil {
		return pkgError.ValidationError("validate change email request: " + err.Error())
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
