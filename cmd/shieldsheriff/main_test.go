//go:build windows

package main

import (
	"slices"
	"testing"

	"shieldsheriff/internal/defender"
)

func TestParseInteractiveCommand(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantCmd     string
		wantReplace bool
		wantElevate bool
	}{
		{
			name:        "no args defaults to empty command without elevation",
			args:        nil,
			wantCmd:     "",
			wantReplace: false,
			wantElevate: false,
		},
		{
			name:        "ui defaults to read-only",
			args:        []string{"ui"},
			wantCmd:     "ui",
			wantReplace: false,
			wantElevate: false,
		},
		{
			name:        "ui with --elevate enables elevation",
			args:        []string{"UI", "--elevate"},
			wantCmd:     "ui",
			wantReplace: false,
			wantElevate: true,
		},
		{
			name:        "tray with -e and --replace",
			args:        []string{"tray", "-e", "--replace"},
			wantCmd:     "tray",
			wantReplace: true,
			wantElevate: true,
		},
		{
			name:        "no-elevate overrides --elevate",
			args:        []string{"dashboard", "--elevate", "--no-elevate"},
			wantCmd:     "dashboard",
			wantReplace: false,
			wantElevate: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd, opts := parseInteractiveCommand(tc.args)
			if cmd != tc.wantCmd {
				t.Fatalf("cmd = %q, want %q", cmd, tc.wantCmd)
			}
			if opts.replace != tc.wantReplace {
				t.Fatalf("replace = %v, want %v", opts.replace, tc.wantReplace)
			}
			if opts.elevate != tc.wantElevate {
				t.Fatalf("elevate = %v, want %v", opts.elevate, tc.wantElevate)
			}
		})
	}
}

func TestStripElevateFlags(t *testing.T) {
	clean, want := stripElevateFlags([]string{"--preset", "workstation", "--elevate"})
	if !want {
		t.Fatal("expected wantElevate=true")
	}
	if !slices.Equal(clean, []string{"--preset", "workstation"}) {
		t.Fatalf("unexpected cleaned args: %v", clean)
	}
}

func TestApplySetArgsStrictValidation(t *testing.T) {
	base := defender.DefaultPolicy()

	// Valid inputs
	pol, err := applySetArgs(base, []string{"realtime=enable", "behavior=off", "cloud=basic", "samples=never", "network=audit", "nags=off", "systray=mute"})
	if err != nil {
		t.Fatalf("expected valid set args to succeed, got %v", err)
	}
	if !pol.RealtimeProtection || pol.BehaviorMonitoring || pol.CloudProtection != 1 || pol.SampleSubmission != 2 || pol.NetworkProtection != 2 || !pol.SuppressAllNags || !pol.MuteWindowsSecSystray {
		t.Fatalf("unexpected parsed policy: %+v", pol)
	}

	// Unknown / typo values MUST fail with an error rather than flipping protection OFF!
	badCases := [][]string{
		{"realtime=maybe"},
		{"realtime=enbaled"},
		{"network=strict"},
		{"cloud=ultra"},
		{"samples=sometimes"},
		{"nags=quietly"},
		{"systray=invisible"},
		{"nonexistent=on"},
	}
	for _, tc := range badCases {
		if _, err := applySetArgs(base, tc); err == nil {
			t.Fatalf("expected error for invalid set args %v, got nil", tc)
		}
	}
}
