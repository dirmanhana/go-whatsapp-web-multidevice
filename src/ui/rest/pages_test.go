package rest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestExtractAppCSS_LocatesStyleBlock guards the parser that pulls the
// dashboard's compiled stylesheet out of the gowa-ui bundle. The real bundle
// opens its <style> tag with attributes and a large minified body, so the
// extraction must be location-based, not literal-match based.
func TestExtractAppCSS_LocatesStyleBlock(t *testing.T) {
	html := []byte(`<html><head>
<link rel="icon" href="data:image/png;base64,abc">
<style rel="stylesheet" crossorigin>
/*! tailwindcss v4.3.2 */
.bg-card{background:var(--card)}
</style>
</head><body></body></html>`)

	css := extractAppCSS(html)
	assert.Equal(t, "\n/*! tailwindcss v4.3.2 */\n.bg-card{background:var(--card)}\n", css)
}

func TestExtractAppCSS_MissingStyleReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", extractAppCSS([]byte(`<html><body>plain</body></html>`)), "no style block -> empty")
	assert.Equal(t, "", extractAppCSS(nil), "nil input -> empty")
	assert.Equal(t, "", extractAppCSS([]byte(`<html><style>never closed`)), "unterminated block -> empty")
}