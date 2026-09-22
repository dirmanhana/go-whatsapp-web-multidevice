package uiasset

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// dashboardFixture returns the runtime-cached dashboard HTML when present, so
// tests exercise the exact bundle this server ships. Skips when the cache has
// not been populated yet (e.g. a fresh checkout before first run).
func dashboardFixture(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "storages", "ui", "index.html")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("dashboard cache not populated yet; skipping bundle-specific checks")
	}
	assert.NoError(t, err)
	return data
}

func TestApplyAuthUIPatch_RemovesServerURLField(t *testing.T) {
	content := dashboardFixture(t)

	patched := ApplyAuthUIPatch(content, "")
	html := string(patched)

	assert.NotContains(t, html, "server-url", "server URL field must be removed")
	assert.NotContains(t, html, "Server URL", "server URL label must be removed")
}

func TestApplyAuthUIPatch_SameOriginLogin(t *testing.T) {
	content := dashboardFixture(t)

	patched := string(ApplyAuthUIPatch(content, ""))

	assert.NotContains(t, patched, "let n=await i(a,s||void 0,l||void 0);",
		"login submit must not read the removed server URL state")
	assert.Contains(t, patched, "let n=await i(window.location.origin,s||void 0,l||void 0);",
		"login submit must probe the same origin")
}

func TestApplyAuthUIPatch_InjectsRegisterForm(t *testing.T) {
	content := dashboardFixture(t)

	patched := string(ApplyAuthUIPatch(content, ""))

	assert.Contains(t, patched, "gowa-register-modal", "register modal must be injected")
	assert.Contains(t, patched, "/auth/register", "register form must call the register endpoint")
	assert.Contains(t, patched, "gowa-ui.connection.v1", "register flow must write the dashboard's zustand key")
	assert.Contains(t, patched, "window.location.origin", "register flow must store the same origin as baseUrl")
}

func TestApplyAuthUIPatch_CopyNoLongerMentionsServerURL(t *testing.T) {
	content := dashboardFixture(t)

	patched := string(ApplyAuthUIPatch(content, ""))

	assert.Contains(t, patched, "Your credentials are stored in this browser only.")
	assert.NotContains(t, patched, "The server URL and optional basic-auth credentials are stored in this browser only.")
}

// TestApplyAuthUIPatch_LogoutOnlyOnCredentialFailure guards the axios
// response interceptor: a non-auth 401 (e.g. WhatsApp disconnected →
// SERVICE_UNAVAILABLE) must not mark the session as unauthorized.
func TestApplyAuthUIPatch_LogoutOnlyOnCredentialFailure(t *testing.T) {
	content := dashboardFixture(t)

	patched := string(ApplyAuthUIPatch(content, ""))

	assert.Contains(t, patched, "t.code===`UNAUTHORIZED`&&eE.getState().markUnauthorized()",
		"logout must only fire for genuine credential failures")
	assert.NotContains(t, patched, "t.status===401&&eE.getState().markUnauthorized()",
		"bare 401 must not trigger logout")
}

// TestApplyAuthUIPatch_LeavesUnknownBundleAlone guards graceful degradation:
// when upstream changes the dashboard so a marker no longer matches, the
// remaining patches must still apply and no partial marker may corrupt output.
func TestApplyAuthUIPatch_LeavesUnknownBundleAlone(t *testing.T) {
	content := []byte(`<html><body>no known markers here</body></html>`)

	patched := string(ApplyAuthUIPatch(content, ""))

	assert.Contains(t, patched, "gowa-register-modal", "injection is anchored on </body> only")
	assert.Contains(t, patched, "data-gowa-menu", "sidebar navigation is anchored on </body> only")
	assert.NotContains(t, patched, loginSubmitOrigin, "no bundle marker matched, so no login rewrite")
	// ApplyAuthUIPatch substitutes __GOWA_BASE__ before injecting, so revert
	// with the same substituted string.
	entry := strings.ReplaceAll(authEntryInjection, "__GOWA_BASE__", "")
	reverted := strings.ReplaceAll(strings.ReplaceAll(patched, authUIInjection, ""), entry, "</body>")
	assert.Equal(t, reverted, string(content),
		"reverting both injections must reproduce the original content exactly")
}

// TestApplyAuthUIPatch_InjectsSidebarMenu guards the navigation the patch
// adds for the pages this server hosts itself: an "Account settings" item for
// every signed-in user and a "Users" item whose visibility is driven by
// GET /auth/me (never by the client alone). The rows mirror the dashboard's
// own sidebar item classes and navigate via plain anchors (full page loads),
// because the SPA router would otherwise swallow /account and /admin.
func TestApplyAuthUIPatch_InjectsSidebarMenu(t *testing.T) {
	content := dashboardFixture(t)

	patched := string(ApplyAuthUIPatch(content, ""))

	assert.Contains(t, patched, "data-gowa-menu", "sidebar group must be injected")
	assert.Contains(t, patched, "Account settings", "account settings item must be injected")
	assert.Contains(t, patched, "Users", "admin users item must be injected")
	assert.Contains(t, patched, "'/account'", "account settings item must link to /account")
	assert.Contains(t, patched, "'/admin'", "users item must link to /admin")
	assert.Contains(t, patched, "fetch(window.location.origin+'/auth/me'", "admin visibility must come from the server's is_admin flag")
	assert.Contains(t, patched, "data-gowa-admin", "admin item must be flagged for server-driven visibility")
	assert.Contains(t, patched, "hover:bg-sidebar-accent/50", "rows must reuse the dashboard's sidebar item styling")
}

// TestApplyAuthUIPatch_BakesBasePathIntoNavigation guards deep links behind a
// non-empty AppBasePath: the injected anchors must carry the base prefix.
func TestApplyAuthUIPatch_BakesBasePathIntoNavigation(t *testing.T) {
	content := dashboardFixture(t)

	patched := string(ApplyAuthUIPatch(content, "/gowa"))

	assert.Contains(t, patched, "BASE='/gowa'", "base path must be baked into the injected script")
	assert.NotContains(t, patched, "__GOWA_BASE__", "placeholder must always be substituted")
}
