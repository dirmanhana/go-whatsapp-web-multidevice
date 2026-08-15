package error

import "net/http"

type LoginError string

// Error for complying the error interface
func (e LoginError) Error() string {
	return string(e)
}

// ErrCode will return the error code based on the error data type
func (e LoginError) ErrCode() string {
	return "ALREADY_LOGGED_IN"
}

// StatusCode will return the HTTP status code based on the error data type
func (e LoginError) StatusCode() int {
	return http.StatusBadRequest
}

type AuthError string

func (err AuthError) Error() string {
	return string(err)
}

// ErrCode will return the error code based on the error data type
func (err AuthError) ErrCode() string {
	return "AUTHENTICATION_ERROR"
}

// StatusCode will return the HTTP status code based on the error data type
func (err AuthError) StatusCode() int {
	return http.StatusUnauthorized
}

type qrChannelError string

func (err qrChannelError) Error() string {
	return string(err)
}

// ErrCode will return the error code based on the error data type
func (err qrChannelError) ErrCode() string {
	return "QR_CHANNEL_ERROR"
}

// StatusCode will return the HTTP status code based on the error data type
func (err qrChannelError) StatusCode() int {
	return http.StatusInternalServerError
}

type sessionSavedError string

func (err sessionSavedError) Error() string {
	return string(err)
}

// ErrCode will return the error code based on the error data type
func (err sessionSavedError) ErrCode() string {
	return "SESSION_SAVED_ERROR"
}

// StatusCode will return the HTTP status code based on the error data type
func (err sessionSavedError) StatusCode() int {
	return http.StatusInternalServerError
}

type notFoundError string

func (err notFoundError) Error() string {
	return string(err)
}

// ErrCode will return the error code based on the error data type
func (err notFoundError) ErrCode() string {
	return "NOT_FOUND"
}

// StatusCode will return the HTTP status code based on the error data type
func (err notFoundError) StatusCode() int {
	return http.StatusNotFound
}

type serviceUnavailableError string

func (err serviceUnavailableError) Error() string {
	return string(err)
}

// ErrCode will return the error code based on the error data type
func (err serviceUnavailableError) ErrCode() string {
	return "SERVICE_UNAVAILABLE"
}

// StatusCode will return the HTTP status code based on the error data type
func (err serviceUnavailableError) StatusCode() int {
	return http.StatusServiceUnavailable
}

var (
	ErrAlreadyLoggedIn = LoginError("you are already logged in.")
	// ErrNotConnected, ErrNotLoggedIn and ErrReconnect describe the WhatsApp
	// service state (disconnected / no session / connect failure), not the
	// caller's credentials. They must NOT be 401: the browser dashboard logs
	// the user out on any 401, so a temporarily disconnected device would
	// otherwise kick users back to the login page.
	ErrNotConnected    = serviceUnavailableError("you are not connect to services server, please reconnect")
	ErrNotLoggedIn     = serviceUnavailableError("you are not logged in")
	ErrReconnect       = serviceUnavailableError("reconnect error")
	ErrQrChannel       = qrChannelError("QR channel error")
	ErrSessionSaved   = sessionSavedError("your session have been saved, please wait to connect 2 second and refresh again")
	ErrDeviceNotFound = notFoundError("device not found")
)
