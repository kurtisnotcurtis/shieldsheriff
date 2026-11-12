package version

import (
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
