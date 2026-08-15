package middleware

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAuthRateLimitTestApp(max int, window time.Duration) *fiber.App {
	app := fiber.New()
	app.Post("/auth/login", AuthRateLimiter(max, window), func(c fiber.Ctx) error {
		if c.Get("X-Fail") == "1" {
			return c.SendStatus(fiber.StatusUnauthorized)
		}
		return c.SendStatus(fiber.StatusOK)
	})
	return app
}

func postLogin(t *testing.T, app *fiber.App, fail bool) int {
	t.Helper()
	req := httptest.NewRequest("POST", "/auth/login", nil)
	if fail {
		req.Header.Set("X-Fail", "1")
	}
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestAuthRateLimiterBlocksAfterMaxFailures(t *testing.T) {
	app := newAuthRateLimitTestApp(3, time.Minute)

	for i := 0; i < 3; i++ {
		assert.Equal(t, fiber.StatusUnauthorized, postLogin(t, app, true), "attempt %d should be counted", i+1)
	}
	assert.Equal(t, fiber.StatusTooManyRequests, postLogin(t, app, true), "4th failed attempt must be limited")
}

func TestAuthRateLimiterIgnoresSuccessfulAttempts(t *testing.T) {
	app := newAuthRateLimitTestApp(3, time.Minute)

	// Successful logins never count toward the limit.
	for i := 0; i < 5; i++ {
		assert.Equal(t, fiber.StatusOK, postLogin(t, app, false))
	}
	// A single failure is still allowed afterwards.
	assert.Equal(t, fiber.StatusUnauthorized, postLogin(t, app, true))
}

func TestAuthRateLimiterDisabledPassesThrough(t *testing.T) {
	app := newAuthRateLimitTestApp(0, time.Minute)

	for i := 0; i < 20; i++ {
		assert.Equal(t, fiber.StatusUnauthorized, postLogin(t, app, true))
	}
}