package version

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionMetadata(t *testing.T) {
	info := Info()
	if info.Version != Version {
		t.Fatalf("expected version %q, got %q", Version, info.Version)
	}
	if !strings.HasPrefix(info.Scheme, "CalVer") {
		t.Fatalf("expected CalVer scheme, got %q", info.Scheme)
	}
	if !strings.Contains(Short(), Version) {
		t.Fatalf("expected Short() to contain %q, got %q", Version, Short())
	}
	if !strings.Contains(Summary(), TestedDefenderPlatform) {
		t.Fatalf("expected Summary() to contain platform %q", TestedDefenderPlatform)
	}
}

func TestVersionSync(t *testing.T) {
	vjBytes, err := os.ReadFile(filepath.Join("..", "..", "VERSION.json"))
	if err != nil {
		t.Fatalf("read VERSION.json: %v", err)
	}
	var vj struct {
		Version    string `json:"version"`
		ReleasedOn string `json:"releasedOn"`
	}
	if err := json.Unmarshal(vjBytes, &vj); err != nil {
		t.Fatalf("parse VERSION.json: %v", err)
	}
	if vj.Version != Version {
		t.Fatalf("VERSION.json version %q != version.Version %q", vj.Version, Version)
	}
	if vj.ReleasedOn != ReleasedOn {
		t.Fatalf("VERSION.json releasedOn %q != version.ReleasedOn %q", vj.ReleasedOn, ReleasedOn)
	}

	clBytes, err := os.ReadFile(filepath.Join("..", "..", "CHANGELOG.md"))
	if err != nil {
		t.Fatalf("read CHANGELOG.md: %v", err)
	}
	heading := "## [" + vj.Version + "]"
	if !strings.Contains(string(clBytes), heading) {
		t.Fatalf("CHANGELOG.md missing release section %q", heading)
	}
}
