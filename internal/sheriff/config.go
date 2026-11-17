package sheriff

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"shieldsheriff/internal/defender"
)

// AuditEntry records an action taken by ShieldSheriff.
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Category  string    `json:"category"` // "ELECT", "ENFORCE", "DRIFT", "STANDDOWN", "SCAN"
	Message   string    `json:"message"`
}

const configFileName = "config.json"

// ConfigPath returns the path to config.json.
// Prefers %ProgramData%\ShieldSheriff\config.json if it exists or if elevated,
// falling back to %LOCALAPPDATA%\ShieldSheriff\config.json.
func ConfigPath() string {
	progData := os.Getenv("ProgramData")
	if progData == "" {
		progData = `C:\ProgramData`
	}
	sysPath := filepath.Join(progData, "ShieldSheriff", configFileName)

	if defender.IsProcessElevated() {
		return sysPath
	}
	if _, err := os.Stat(sysPath); err == nil {
		return sysPath
	}

	localApp := os.Getenv("LOCALAPPDATA")
	if localApp != "" {
		return filepath.Join(localApp, "ShieldSheriff", configFileName)
	}
	exe, err := os.Executable()
	if err == nil {
		return filepath.Join(filepath.Dir(exe), configFileName)
	}
	return configFileName
}

// LoadOrders reads config.json from disk, or initializes defaults if no config file exists yet.
func LoadOrders() (defender.StandingOrders, string, error) {
	path := ConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		def := defender.DefaultStandingOrders()
		return def, path, err
	}
	var orders defender.StandingOrders
	if err := json.Unmarshal(data, &orders); err != nil {
		def := defender.DefaultStandingOrders()
		return def, path, err
	}
	return orders, path, nil
}

// SaveOrders writes config.json to disk.
func SaveOrders(orders defender.StandingOrders) (string, error) {
	orders.UpdatedAt = time.Now()
	path := ConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		// Fallback to LOCALAPPDATA if ProgramData is not writable
		localApp := os.Getenv("LOCALAPPDATA")
		if localApp != "" {
			path = filepath.Join(localApp, "ShieldSheriff", configFileName)
			_ = os.MkdirAll(filepath.Dir(path), 0755)
		}
	}
	data, err := json.MarshalIndent(orders, "", "  ")
	if err != nil {
		return path, err
	}
	err = os.WriteFile(path, data, 0644)
	return path, err
}
