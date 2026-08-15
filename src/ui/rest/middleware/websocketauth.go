package middleware

import (
	"strings"

	"github.com/gofiber/contrib/v3/websocket"
	"github.com/gofiber/fiber/v3"
)

// WebsocketQueryAuth lets browser WebSocket clients authenticate with a query
// parameter, because the browser WebSocket API cannot set an Authorization
// header and userinfo in WS URLs is rejected per spec. Two forms are
// restored into the header before the auth middleware runs:
//   - ?authorization=<base64(user:pass)> for basic auth
//   - ?token=<bearer-token> for multi-user bearer auth
func WebsocketQueryAuth() fiber.Handler {
	return func(c fiber.Ctx) error {
		if websocket.IsWebSocketUpgrade(c) && len(c.Request().Header.Peek(fiber.HeaderAuthorization)) == 0 {
			if q := c.Query("authorization"); q != "" {
				// fasthttp decodes '+' as space; base64 never contains spaces,
				// so restoring '+' is lossless.
				token := strings.ReplaceAll(q, " ", "+")
				c.Request().Header.Set(fiber.HeaderAuthorization, "Basic "+token)
			} else if token := c.Query("token"); token != "" {
				c.Request().Header.Set(fiber.HeaderAuthorization, "Bearer "+token)
			}
		}
		return c.Next()
	}
}
