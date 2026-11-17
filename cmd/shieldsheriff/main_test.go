package main

import "testing"

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
