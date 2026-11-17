package sheriff

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"shieldsheriff/internal/version"
)

const latestReleaseAPI = "https://api.github.com/repos/kurtisnotcurtis/shieldsheriff/releases/latest"

// UpdateInfo describes the result of checking GitHub for a newer ShieldSheriff release.
type UpdateInfo struct {
	Checked        bool      `json:"checked"`
	CheckedAt      time.Time `json:"checkedAt,omitempty"`
	Available      bool      `json:"available"`
	CurrentVersion string    `json:"currentVersion"`
	LatestVersion  string    `json:"latestVersion,omitempty"`
	ReleaseURL     string    `json:"releaseUrl,omitempty"`
	Error          string    `json:"error,omitempty"`
}

// CheckLatestRelease queries GitHub Releases for a newer version of ShieldSheriff.
func CheckLatestRelease() UpdateInfo {
	info := UpdateInfo{
		Checked:        true,
		CheckedAt:      time.Now(),
		CurrentVersion: version.Version,
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, latestReleaseAPI, nil)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	req.Header.Set("User-Agent", "ShieldSheriff/"+version.Version)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		info.Error = err.Error()
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		info.Error = fmt.Sprintf("GitHub API returned HTTP %d", resp.StatusCode)
		return info
	}

	var payload struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		info.Error = err.Error()
		return info
	}

	latest := strings.TrimPrefix(strings.TrimSpace(payload.TagName), "v")
	info.LatestVersion = latest
	info.ReleaseURL = payload.HTMLURL
	info.Available = isNewerVersion(latest, version.Version)
	return info
}

func isNewerVersion(candidate, current string) bool {
	cParts := parseVerParts(candidate)
	curParts := parseVerParts(current)
	n := len(cParts)
	if len(curParts) > n {
		n = len(curParts)
	}
	for i := 0; i < n; i++ {
		var a, b int
		if i < len(cParts) {
			a = cParts[i]
		}
		if i < len(curParts) {
			b = curParts[i]
		}
		if a > b {
			return true
		}
		if a < b {
			return false
		}
	}
	return false
}

func parseVerParts(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		v = v[:idx]
	}
	raw := strings.Split(v, ".")
	out := make([]int, 0, len(raw))
	for _, s := range raw {
		n, err := strconv.Atoi(s)
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}
