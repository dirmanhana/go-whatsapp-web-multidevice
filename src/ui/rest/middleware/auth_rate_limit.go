package middleware

import (
	"time"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/pkg/utils"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
)

// AuthRateLimiter returns a per-IP rate limiter for the auth endpoints.
// Only failed attempts (HTTP status >= 400, e.g. wrong credentials) count
// toward the limit, so legitimate users who authenticate successfully are
// never penalized while brute-force attempts are throttled. A max <= 0
// disables the limiter entirely (pass-through).
func AuthRateLimiter(max int, window time.Duration) fiber.Handler {
	if max <= 0 {
		return func(c fiber.Ctx) error {
			return c.Next()
		}
	}
	return limiter.New(limiter.Config{
		Max:                   max,
		Expiration:            window,
		SkipSuccessfulRequests: true,
		LimitReached: func(c fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(utils.ResponseData{
				Status:  fiber.StatusTooManyRequests,
				Code:    "TOO_MANY_REQUESTS",
				Message: "too many failed attempts from this IP, try again later",
				Results: nil,
			})
		},
	})
}