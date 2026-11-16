package tray

import (
	"slices"
	"testing"
)

func TestCreateSheriffBadgeIcon(t *testing.T) {
	for _, kind := range []BadgeKind{BadgeGold, BadgeStandDown, BadgeWarning} {
		hIcon := CreateSheriffBadgeIcon(kind)
		if hIcon == 0 {
			t.Fatalf("expected non-zero HICON handle for kind %v", kind)
		}
	}
}

func TestSheriffBadgeIconAccentColors(t *testing.T) {
	const size = 32
	goldPixels := make([]uint32, size*size)
	standDownPixels := make([]uint32, size*size)
	warningPixels := make([]uint32, size*size)

	renderSheriffBadgePixels(BadgeGold, size, goldPixels)
	renderSheriffBadgePixels(BadgeStandDown, size, standDownPixels)
	renderSheriffBadgePixels(BadgeWarning, size, warningPixels)

	if slices.Equal(goldPixels, standDownPixels) {
		t.Fatal("expected BadgeGold and BadgeStandDown icons to differ")
	}
	if slices.Equal(goldPixels, warningPixels) {
		t.Fatal("expected BadgeGold and BadgeWarning icons to differ")
	}
	if slices.Equal(standDownPixels, warningPixels) {
		t.Fatal("expected BadgeStandDown and BadgeWarning icons to differ")
	}

	// Verify exact opaque accent color pixels appear for each state:
	// Gold: (250, 204, 21) -> 0xFFFACC15
	// Stand-Down Cyan: (56, 189, 248) -> 0xFF38BDF8
	// Warning Amber: (251, 146, 60) -> 0xFFFB923C
	if !slices.Contains(goldPixels, 0xFFFACC15) {
		t.Fatal("expected BadgeGold icon to contain gold accent pixels (0xFFFACC15)")
	}
	if !slices.Contains(standDownPixels, 0xFF38BDF8) {
		t.Fatal("expected BadgeStandDown icon to contain cyan accent pixels (0xFF38BDF8)")
	}
	if !slices.Contains(warningPixels, 0xFFFB923C) {
		t.Fatal("expected BadgeWarning icon to contain amber accent pixels (0xFFFB923C)")
	}
}
