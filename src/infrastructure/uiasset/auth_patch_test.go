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

	patched := ApplyAuthUIPatch(content)
	html := string(patched)

	assert.NotContains(t, html, "server-url", "server URL field must be removed")
	assert.NotContains(t, html, "Server URL", "server URL label must be removed")
}

func TestApplyAuthUIPatch_SameOriginLogin(t *testing.T) {
	content := dashboardFixture(t)

	patched := string(ApplyAuthUIPatch(content))

	assert.NotContains(t, patched, "let n=await i(a,s||void 0,l||void 0);",
		"login submit must not read the removed server URL state")
	assert.Contains(t, patched, "let n=await i(window.location.origin,s||void 0,l||void 0);",
		"login submit must probe the same origin")
}

func TestApplyAuthUIPatch_InjectsRegisterForm(t *testing.T) {
	content := dashboardFixture(t)

	patched := string(ApplyAuthUIPatch(content))

	assert.Contains(t, patched, "gowa-register-modal", "register modal must be injected")
	assert.Contains(t, patched, "/auth/register", "register form must call the register endpoint")
	assert.Contains(t, patched, "gowa-ui.connection.v1", "register flow must write the dashboard's zustand key")
	assert.Contains(t, patched, "window.location.origin", "register flow must store the same origin as baseUrl")
}

func TestApplyAuthUIPatch_CopyNoLongerMentionsServerURL(t *testing.T) {
	content := dashboardFixture(t)

	patched := string(ApplyAuthUIPatch(content))

	assert.Contains(t, patched, "Your credentials are stored in this browser only.")
	assert.NotContains(t, patched, "The server URL and optional basic-auth credentials are stored in this browser only.")
}

// TestApplyAuthUIPatch_LeavesUnknownBundleAlone guards graceful degradation:
// when upstream changes the dashboard so a marker no longer matches, the
// remaining patches must still apply and no partial marker may corrupt output.
func TestApplyAuthUIPatch_LeavesUnknownBundleAlone(t *testing.T) {
	content := []byte(`<html><body>no known markers here</body></html>`)

	patched := string(ApplyAuthUIPatch(content))

	assert.Contains(t, patched, "gowa-register-modal", "injection is anchored on </body> only")
	assert.NotContains(t, patched, loginSubmitOrigin, "no bundle marker matched, so no login rewrite")
	assert.Equal(t, strings.ReplaceAll(patched, authUIInjection, "</body>"), string(content),
		"reverting the injection must reproduce the original content exactly")
}