package error

import "net/http"

type UnauthorizedError string

func (e UnauthorizedError) Error() string {
	return string(e)
}

// ErrCode will return the error code based on the error data type
func (e UnauthorizedError) ErrCode() string {
	return "UNAUTHORIZED"
}

// StatusCode will return the HTTP status code based on the error data type
func (e UnauthorizedError) StatusCode() int {
	return http.StatusUnauthorized
}

type InvalidCredentialsError string

func (e InvalidCredentialsError) Error() string {
	return string(e)
}

// ErrCode will return the error code based on the error data type
func (e InvalidCredentialsError) ErrCode() string {
	return "INVALID_CREDENTIALS"
}

// StatusCode will return the HTTP status code based on the error data type
func (e InvalidCredentialsError) StatusCode() int {
	return http.StatusUnauthorized
}

type UserAlreadyExistsError string

func (e UserAlreadyExistsError) Error() string {
	return string(e)
}

// ErrCode will return the error code based on the error data type
func (e UserAlreadyExistsError) ErrCode() string {
	return "USER_ALREADY_EXISTS"
}

// StatusCode will return the HTTP status code based on the error data type
func (e UserAlreadyExistsError) StatusCode() int {
	return http.StatusConflict
}

type DeviceLimitReachedError string

func (e DeviceLimitReachedError) Error() string {
	return string(e)
}

// ErrCode will return the error code based on the error data type
func (e DeviceLimitReachedError) ErrCode() string {
	return "DEVICE_LIMIT_REACHED"
}

// StatusCode will return the HTTP status code based on the error data type
func (e DeviceLimitReachedError) StatusCode() int {
	return http.StatusTooManyRequests
}

type ForbiddenError string

func (e ForbiddenError) Error() string {
	return string(e)
}

// ErrCode will return the error code based on the error data type
func (e ForbiddenError) ErrCode() string {
	return "FORBIDDEN"
}

// StatusCode will return the HTTP status code based on the error data type
func (e ForbiddenError) StatusCode() int {
	return http.StatusForbidden
}

type UserDisabledError string

func (e UserDisabledError) Error() string {
	return string(e)
}

// ErrCode will return the error code based on the error data type
func (e UserDisabledError) ErrCode() string {
	return "USER_DISABLED"
}

// StatusCode will return the HTTP status code based on the error data type
func (e UserDisabledError) StatusCode() int {
	return http.StatusForbidden
}

var (
	ErrUnauthorized        = UnauthorizedError("authentication required: login via POST /auth/login and send the token as 'Authorization: Bearer <token>'")
	ErrInvalidCredentials  = InvalidCredentialsError("invalid username or password")
	ErrUserAlreadyExists   = UserAlreadyExistsError("username already exists")
	ErrDeviceLimitReached  = DeviceLimitReachedError("device limit reached for this user")
	ErrRegistrationBlocked = UnauthorizedError("registration is disabled")
	ErrForbidden           = ForbiddenError("insufficient permissions: admin access required")
	ErrUserDisabled        = UserDisabledError("account is disabled by the administrator")
	ErrCannotDisableSelf   = ForbiddenError("an admin cannot disable their own account")
)
