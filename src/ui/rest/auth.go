package rest

import (
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

	app.Post("/auth/register", rest.Register)
	app.Post("/auth/login", rest.Login)
	app.Post("/auth/logout", rest.Logout)
	app.Get("/auth/me", rest.Me)

	return rest
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