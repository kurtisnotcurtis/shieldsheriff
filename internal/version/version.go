package version

import "fmt"

// CalVer release metadata (YYYY.0M.MICRO) tracking Windows 11 Defender platform evolution.
// Version and ReleasedOn can be overridden at build time via -ldflags -X from VERSION.json.
var (
	// Version is the current CalVer release of ShieldSheriff.
	Version = "2026.11.4"

	// ReleasedOn is the ISO-8601 release date (EST/EDT).
	ReleasedOn = "2026-11-16"
)

const (
	// Codename identifies the release milestone.
	Codename = "Peacekeeper"

	// TestedWinBuild is the primary Windows 11 build baseline verified against this release.
	TestedWinBuild = "Windows 11 24H2 / 25H2 (26100.2314+)"

	// TestedDefenderPlatform is the Microsoft Defender Antivirus platform baseline (MpCmdRun / MsMpEng).
	TestedDefenderPlatform = "4.18.26100.5"

	// TestedWscSchema describes the Windows Security Center & Defender policy schema baseline.
	TestedWscSchema = "WSC-2026.11 (DisableNotifications + DisableEnhancedNotifications + DCOM MSFT_MpPreference)"
)

// Metadata holds structured version and Defender compatibility metadata for CLI/UI/JSON reporting.
type Metadata struct {
	Version                string `json:"version"`
	Scheme                 string `json:"scheme"`
	Codename               string `json:"codename"`
	ReleasedOn             string `json:"releasedOn"`
	TestedWinBuild         string `json:"testedWinBuild"`
	TestedDefenderPlatform string `json:"testedDefenderPlatform"`
	TestedWscSchema        string `json:"testedWscSchema"`
}

// Info returns the current release Metadata.
func Info() Metadata {
	return Metadata{
		Version:                Version,
		Scheme:                 "CalVer (YYYY.0M.MICRO)",
		Codename:               Codename,
		ReleasedOn:             ReleasedOn,
		TestedWinBuild:         TestedWinBuild,
		TestedDefenderPlatform: TestedDefenderPlatform,
		TestedWscSchema:        TestedWscSchema,
	}
}

// Short returns a compact single-line version banner.
func Short() string {
	return fmt.Sprintf("ShieldSheriff v%s (%s)", Version, Codename)
}

// Summary returns a multi-line human-readable version & platform compatibility summary.
func Summary() string {
	return fmt.Sprintf(
		"ShieldSheriff v%s %q (CalVer YYYY.0M.MICRO — released %s)\n"+
			"  Windows Baseline  : %s\n"+
			"  Defender Platform : %s\n"+
			"  Policy/WMI Schema : %s",
		Version, Codename, ReleasedOn,
		TestedWinBuild, TestedDefenderPlatform, TestedWscSchema,
	)
}
