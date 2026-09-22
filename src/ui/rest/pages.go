package rest

import (
	"embed"
	"strings"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	"github.com/gofiber/fiber/v3"
)

// templates holds the two self-contained HTML pages this package serves: the
// admin panel (/admin) and the self-service account settings (/account). Their
// CSS and JS are separate files inlined at serve time, so the pages keep one
// copy of the shared helpers without needing extra asset routes.
//
//go:embed templates
var templates embed.FS

// InitRestPages registers the HTML shells for the admin panel and the account
// settings page. Both are reachable without a token on purpose, exactly like
// the dashboard at "/": the pages carry no data, only markup. Everything their
// JavaScript fetches (/auth/me, /auth/users, ...) still runs through
// AuthMiddleware, and the admin panel re-checks is_admin in the browser before
// rendering anything (the server enforces it again on every admin call).
func InitRestPages(app fiber.Router) {
	app.Get("/admin", servePage("admin.html"))
	app.Get("/account", servePage("account.html"))
}

func servePage(name string) fiber.Handler {
	return func(c fiber.Ctx) error {
		content, err := renderPage(name)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "page unavailable")
		}
		c.Type("html")
		c.Set(fiber.HeaderCacheControl, "no-cache")
		return c.Send(content)
	}
}

// renderPage assembles one page: shared CSS and JS are inlined into the
// markup, and {{BASE_PATH}} is substituted everywhere (markup and injected
// scripts alike) so the pages work behind a non-empty AppBasePath too.
func renderPage(name string) ([]byte, error) {
	pageBytes, err := templates.ReadFile("templates/" + name)
	if err != nil {
		return nil, err
	}
	cssBytes, err := templates.ReadFile("templates/app.css")
	if err != nil {
		return nil, err
	}
	jsBytes, err := templates.ReadFile("templates/app.js")
	if err != nil {
		return nil, err
	}

	html := strings.ReplaceAll(string(pageBytes), "__INLINE_CSS__", string(cssBytes))
	html = strings.ReplaceAll(html, "__INLINE_JS__", string(jsBytes))
	html = strings.ReplaceAll(html, "{{BASE_PATH}}", config.AppBasePath)
	return []byte(html), nil
}
