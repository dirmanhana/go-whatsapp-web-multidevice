package rest

import (
	"strconv"
	"strings"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	domainAuth "github.com/aldinokemal/go-whatsapp-web-multidevice/domains/auth"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/utils"
	"github.com/aldinokemal/go-whatsapp-web-multidevice/ui/rest/middleware"
	"github.com/gofiber/fiber/v3"
)

type Auth struct {
	Service domainAuth.IAuthUsecase
}

func InitRestAuth(app fiber.Router, service domainAuth.IAuthUsecase) Auth {
	rest := Auth{Service: service}

	authRateLimiter := middleware.AuthRateLimiter(config.AuthRateLimitMax, config.AuthRateLimitWindow)

	app.Post("/auth/register", authRateLimiter, rest.Register)
	app.Post("/auth/login", authRateLimiter, rest.Login)
	app.Post("/auth/logout", rest.Logout)
	app.Post("/auth/logout-all", rest.LogoutAll)
	app.Get("/auth/me", rest.Me)
	app.Get("/auth/sessions", rest.Sessions)
	app.Get("/auth/users", rest.ListUsers)
	// Admin account management. Every handler resolves the caller through the
	// usecase's requireAdmin, so a non-admin gets 403 from the usecase layer
	// even if these paths are reachable.
	app.Post("/auth/users", rest.CreateUser)
	app.Put("/auth/users/:id", rest.UpdateUser)
	app.Post("/auth/users/:id/password", rest.ResetUserPassword)
	app.Delete("/auth/users/:id", rest.DeleteUser)
	app.Post("/auth/users/:id/disable", rest.DisableUser)
	app.Post("/auth/users/:id/enable", rest.EnableUser)
	// Self-service account settings: change own password / email.
	app.Post("/auth/me/password", rest.ChangePassword)
	app.Post("/auth/me/email", rest.ChangeEmail)

	return rest
}

// parseUserID reads the :id route parameter as a positive user id. The error
// it returns is already a Fiber JSON 401/400 response, meant to be returned
// straight from the handler.
func parseUserID(c fiber.Ctx) (int64, error) {
	userID, err := strconv.ParseInt(strings.TrimSpace(c.Params("id")), 10, 64)
	if err != nil || userID <= 0 {
		return 0, c.Status(fiber.StatusBadRequest).JSON(utils.ResponseData{
			Status:  fiber.StatusBadRequest,
			Code:    "BAD_REQUEST",
			Message: "Invalid user id",
			Results: nil,
		})
	}
	return userID, nil
}

func (handler *Auth) Register(c fiber.Ctx) error {
	if !config.AuthAllowRegister {
		return c.Status(fiber.StatusForbidden).JSON(utils.ResponseData{
			Status:  fiber.StatusForbidden,
			Code:    "REGISTRATION_DISABLED",
			Message: "registration is disabled by the server administrator",
			Results: nil,
		})
	}

	var req domainAuth.RegisterRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.ResponseData{
			Status:  fiber.StatusBadRequest,
			Code:    "BAD_REQUEST",
			Message: "Invalid request body",
			Results: nil,
		})
	}

	user, err := handler.Service.Register(c.Context(), req)
	utils.PanicIfNeeded(err)

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "User registered",
		Results: user,
	})
}

func (handler *Auth) Login(c fiber.Ctx) error {
	var req domainAuth.LoginRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.ResponseData{
			Status:  fiber.StatusBadRequest,
			Code:    "BAD_REQUEST",
			Message: "Invalid request body",
			Results: nil,
		})
	}

	response, err := handler.Service.Login(c.Context(), req)
	utils.PanicIfNeeded(err)

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "Login success",
		Results: response,
	})
}

func (handler *Auth) Logout(c fiber.Ctx) error {
	token := middleware.BearerToken(c.Get(fiber.HeaderAuthorization))
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(utils.ResponseData{
			Status:  fiber.StatusUnauthorized,
			Code:    "UNAUTHORIZED",
			Message: "missing Bearer token",
			Results: nil,
		})
	}

	err := handler.Service.Logout(c.Context(), token)
	utils.PanicIfNeeded(err)

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "Logged out",
		Results: nil,
	})
}

func (handler *Auth) LogoutAll(c fiber.Ctx) error {
	err := handler.Service.LogoutAll(c.Context())
	utils.PanicIfNeeded(err)

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "All sessions revoked",
		Results: nil,
	})
}

func (handler *Auth) Sessions(c fiber.Ctx) error {
	sessions, err := handler.Service.Sessions(c.Context())
	utils.PanicIfNeeded(err)

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "Active sessions",
		Results: sessions,
	})
}

func (handler *Auth) ListUsers(c fiber.Ctx) error {
	users, err := handler.Service.ListUsers(c.Context())
	utils.PanicIfNeeded(err)

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "Users",
		Results: users,
	})
}

func (handler *Auth) DisableUser(c fiber.Ctx) error {
	userID, err := parseUserID(c)
	if err != nil {
		return err
	}
	if err := handler.Service.SetUserDisabled(c.Context(), userID, true); err != nil {
		utils.PanicIfNeeded(err)
	}

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "User disabled",
		Results: nil,
	})
}

func (handler *Auth) EnableUser(c fiber.Ctx) error {
	userID, err := parseUserID(c)
	if err != nil {
		return err
	}
	if err := handler.Service.SetUserDisabled(c.Context(), userID, false); err != nil {
		utils.PanicIfNeeded(err)
	}

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "User enabled",
		Results: nil,
	})
}

// CreateUser provisions a new account on an admin's behalf (POST /auth/users).
func (handler *Auth) CreateUser(c fiber.Ctx) error {
	var req domainAuth.AdminCreateUserRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.ResponseData{
			Status:  fiber.StatusBadRequest,
			Code:    "BAD_REQUEST",
			Message: "Invalid request body",
			Results: nil,
		})
	}

	user, err := handler.Service.AdminCreateUser(c.Context(), req)
	utils.PanicIfNeeded(err)

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "User created",
		Results: user,
	})
}

// UpdateUser edits an account's username, email, or admin flag
// (PUT /auth/users/:id).
func (handler *Auth) UpdateUser(c fiber.Ctx) error {
	userID, err := parseUserID(c)
	if err != nil {
		return err
	}
	var req domainAuth.AdminUpdateUserRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.ResponseData{
			Status:  fiber.StatusBadRequest,
			Code:    "BAD_REQUEST",
			Message: "Invalid request body",
			Results: nil,
		})
	}

	user, err := handler.Service.AdminUpdateUser(c.Context(), userID, req)
	utils.PanicIfNeeded(err)

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "User updated",
		Results: user,
	})
}

// ResetUserPassword sets a new password for an account and kills its sessions
// (POST /auth/users/:id/password).
func (handler *Auth) ResetUserPassword(c fiber.Ctx) error {
	userID, err := parseUserID(c)
	if err != nil {
		return err
	}
	var req domainAuth.AdminPasswordRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.ResponseData{
			Status:  fiber.StatusBadRequest,
			Code:    "BAD_REQUEST",
			Message: "Invalid request body",
			Results: nil,
		})
	}

	utils.PanicIfNeeded(handler.Service.AdminSetUserPassword(c.Context(), userID, req.Password))

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "Password updated",
		Results: nil,
	})
}

// DeleteUser removes an account (DELETE /auth/users/:id).
func (handler *Auth) DeleteUser(c fiber.Ctx) error {
	userID, err := parseUserID(c)
	if err != nil {
		return err
	}

	utils.PanicIfNeeded(handler.Service.AdminDeleteUser(c.Context(), userID))

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "User deleted",
		Results: nil,
	})
}

// ChangePassword is the self-service password rotation (POST /auth/me/password).
func (handler *Auth) ChangePassword(c fiber.Ctx) error {
	var req domainAuth.ChangePasswordRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.ResponseData{
			Status:  fiber.StatusBadRequest,
			Code:    "BAD_REQUEST",
			Message: "Invalid request body",
			Results: nil,
		})
	}

	utils.PanicIfNeeded(handler.Service.ChangeOwnPassword(c.Context(), req))

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "Password changed",
		Results: nil,
	})
}

// ChangeEmail is the self-service email change (POST /auth/me/email).
func (handler *Auth) ChangeEmail(c fiber.Ctx) error {
	var req domainAuth.ChangeEmailRequest
	if err := c.Bind().Body(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(utils.ResponseData{
			Status:  fiber.StatusBadRequest,
			Code:    "BAD_REQUEST",
			Message: "Invalid request body",
			Results: nil,
		})
	}

	user, err := handler.Service.ChangeOwnEmail(c.Context(), req)
	utils.PanicIfNeeded(err)

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "Email changed",
		Results: user,
	})
}

func (handler *Auth) Me(c fiber.Ctx) error {
	user, err := handler.Service.Me(c.Context())
	utils.PanicIfNeeded(err)

	return c.JSON(utils.ResponseData{
		Status:  200,
		Code:    "SUCCESS",
		Message: "User info",
		Results: user,
	})
}