package tray

import "testing"

func TestCreateSheriffBadgeIcon(t *testing.T) {
	for _, kind := range []BadgeKind{BadgeGold, BadgeStandDown, BadgeWarning} {
		hIcon := CreateSheriffBadgeIcon(kind)
		if hIcon == 0 {
			t.Fatalf("expected non-zero HICON handle for kind %v", kind)
		}
	}
}
