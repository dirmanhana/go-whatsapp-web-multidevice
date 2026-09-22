package rest

import (
	"bytes"
	"embed"
	"strings"

	"github.com/aldinokemal/go-whatsapp-web-multidevice/config"
	"github.com/gofiber/fiber/v3"
)

// templates holds the two pages this package serves: the admin panel (/admin)
// and the self-service account settings (/account). Their JavaScript is a
// separate file inlined at serve time; the styling is the dashboard's own
// compiled CSS (extracted from the gowa-ui bundle at render time), so both
// pages look and behave like the app instead of carrying a custom theme.
//
//go:embed templates
var templates embed.FS

// InitRestPages registers the HTML shells for the admin panel and the account
// settings page. Both are reachable without a token on purpose, exactly like
// the dashboard at "/": the pages carry no data, only markup. Everything their
// JavaScript fetches (/auth/me, /auth/users, ...) still runs through
// AuthMiddleware, and the admin panel re-checks is_admin in the browser before
// rendering anything (the server enforces it again on every admin call).
//
// dashboard returns the raw gowa-ui HTML so the pages can inline the app's
// compiled stylesheet (fonts, tokens and utility classes stay identical). When
// it yields nothing (cache still warming up), the pages fall back to a minimal
// embedded stylesheet so they remain usable.
func InitRestPages(app fiber.Router, dashboard func() []byte) {
	app.Get("/admin", servePage("admin.html", dashboard))
	app.Get("/account", servePage("account.html", dashboard))
}

func servePage(name string, dashboard func() []byte) fiber.Handler {
	return func(c fiber.Ctx) error {
		content, err := renderPage(name, dashboard)
		if err != nil {
			return fiber.NewError(fiber.StatusInternalServerError, "page unavailable")
		}
		c.Type("html")
		c.Set(fiber.HeaderCacheControl, "no-cache")
		return c.Send(content)
	}
}

// renderPage assembles one page: the dashboard's compiled CSS is inlined as
// __APP_CSS__, the shared JavaScript as __INLINE_JS__, and {{BASE_PATH}} is
// substituted everywhere (markup and injected scripts alike) so the pages work
// behind a non-empty AppBasePath too.
func renderPage(name string, dashboard func() []byte) ([]byte, error) {
	pageBytes, err := templates.ReadFile("templates/" + name)
	if err != nil {
		return nil, err
	}
	jsBytes, err := templates.ReadFile("templates/app.js")
	if err != nil {
		return nil, err
	}

	css := extractAppCSS(dashboard())
	if css == "" {
		// Cache still warming up: fall back to the minimal embedded stylesheet
		// instead of shipping unstyled markup.
		fallback, err := templates.ReadFile("templates/app.css")
		if err != nil {
			return nil, err
		}
		css = string(fallback)
	}

	html := strings.ReplaceAll(string(pageBytes), "__APP_CSS__", css)
	html = strings.ReplaceAll(html, "__INLINE_JS__", string(jsBytes))
	html = strings.ReplaceAll(html, "{{BASE_PATH}}", config.AppBasePath)
	return []byte(html), nil
}

// extractAppCSS returns the dashboard's compiled stylesheet — the content of
// its single <style> block (the tag may carry attributes, so the block is
// located by tag name and closing tag, not by an exact literal).
func extractAppCSS(html []byte) string {
	start := bytes.Index(html, []byte("<style"))
	if start < 0 {
		return ""
	}
	head := bytes.IndexByte(html[start:], '>')
	if head < 0 {
		return ""
	}
	contentStart := start + head + 1
	end := bytes.Index(html[contentStart:], []byte("</style>"))
	if end < 0 {
		return ""
	}
	return string(html[contentStart : contentStart+end])
}
