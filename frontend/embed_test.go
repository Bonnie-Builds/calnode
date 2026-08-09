package frontend

import (
	"strings"
	"testing"
)

func TestInlineScriptCSPHashesCoverGeneratedSPAShell(t *testing.T) {
	hashes := InlineScriptCSPHashes()
	if len(hashes) == 0 {
		t.Fatal("generated SPA shell must expose at least one inline bootstrap hash")
	}
	for _, hash := range hashes {
		if !strings.HasPrefix(hash, "'sha256-") || !strings.HasSuffix(hash, "'") {
			t.Fatalf("invalid CSP hash source %q", hash)
		}
	}
}
