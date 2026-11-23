//go:build windows

package tray

import (
	"slices"
	"testing"
)

func TestCreateSheriffBadgeIcon(t *testing.T) {
	kinds := []BadgeKind{
		BadgePassive,
		BadgePause,
		BadgePresetOnDemand,
		BadgePresetDev,
		BadgePresetQuiet,
		BadgePresetFull,
		BadgePresetCustom,
		BadgeBrand,
	}
	for _, kind := range kinds {
		hIcon := CreateSheriffBadgeIcon(kind)
		if hIcon == 0 {
			t.Fatalf("expected non-zero HICON handle for kind %v", kind)
		}
	}
}

func TestSheriffBadgeIconAccentColors(t *testing.T) {
	const size = 32
	kinds := []BadgeKind{
		BadgePassive,
		BadgePause,
		BadgePresetOnDemand,
		BadgePresetDev,
		BadgePresetQuiet,
		BadgePresetFull,
		BadgePresetCustom,
	}
	rendered := make([][]uint32, len(kinds))
	for i, k := range kinds {
		buf := make([]uint32, size*size)
		renderSheriffBadgePixels(k, size, buf)
		rendered[i] = buf
	}

	for i := 0; i < len(rendered); i++ {
		for j := i + 1; j < len(rendered); j++ {
			if slices.Equal(rendered[i], rendered[j]) {
				t.Fatalf("expected badge %v and %v to differ", kinds[i], kinds[j])
			}
		}
	}

	if !slices.Contains(rendered[0], 0xFF94A3B8) {
		t.Fatal("expected BadgePassive to contain slate shield outline (0xFF94A3B8)")
	}
	if !slices.Contains(rendered[1], 0xFFFB923C) {
		t.Fatal("expected BadgePause to contain amber pause color (0xFFFB923C)")
	}
	if !slices.Contains(rendered[2], 0xFFF87171) {
		t.Fatal("expected BadgePresetOnDemand to contain coral red (0xFFF87171)")
	}
	if !slices.Contains(rendered[3], 0xFF60CDFF) {
		t.Fatal("expected BadgePresetDev to contain sky blue (0xFF60CDFF)")
	}
	if !slices.Contains(rendered[4], 0xFF38BDF8) {
		t.Fatal("expected BadgePresetQuiet to contain cyan shield (0xFF38BDF8)")
	}
	if !slices.Contains(rendered[5], 0xFF4ADE80) {
		t.Fatal("expected BadgePresetFull to contain emerald green (0xFF4ADE80)")
	}
}
