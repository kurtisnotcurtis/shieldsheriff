package sheriff

import "testing"

func TestIsNewerVersion(t *testing.T) {
	cases := []struct {
		cand, cur string
		want      bool
	}{
		{"2026.11.4", "2026.11.3", true},
		{"2026.12.0", "2026.11.9", true},
		{"2027.01.1", "2026.11.3", true},
		{"2026.11.3", "2026.11.3", false},
		{"2026.11.2", "2026.11.3", false},
		{"v2026.11.4", "2026.11.3", true},
	}
	for _, tc := range cases {
		if got := isNewerVersion(tc.cand, tc.cur); got != tc.want {
			t.Fatalf("isNewerVersion(%q, %q) = %v, want %v", tc.cand, tc.cur, got, tc.want)
		}
	}
}
