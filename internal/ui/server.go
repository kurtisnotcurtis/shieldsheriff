package ui

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"shieldsheriff/internal/defender"
	"shieldsheriff/internal/sheriff"
	"shieldsheriff/internal/version"
)

//go:embed dashboard.html
var dashboardHTML []byte

// Server hosts the local ShieldSheriff Command Center UI on 127.0.0.1.
type Server struct {
	gov        *sheriff.Governor
	addr       string
	url        string
	ln         net.Listener
	httpSrv    *http.Server
	onShutdown func()
	openMu     sync.Mutex
	lastOpen   time.Time
}

// StartServer starts the local loopback Command Center HTTP server.
func StartServer(gov *sheriff.Governor, preferredPort int) (*Server, error) {
	var ln net.Listener
	var err error
	if preferredPort > 0 {
		ln, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", preferredPort))
	}
	if ln == nil || err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
	}

	s := &Server{
		gov:  gov,
		addr: ln.Addr().String(),
		url:  "http://" + ln.Addr().String(),
		ln:   ln,
	}
	s.httpSrv = &http.Server{Handler: s.Handler()}

	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			_ = ln.Close()
		}
	}()
	return s, nil
}

// SetOnShutdown registers a callback used when the server initiates a process shutdown (e.g. UAC relaunch).
func (s *Server) SetOnShutdown(fn func()) {
	s.onShutdown = fn
}

// Shutdown gracefully stops the Command Center HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv != nil {
		return s.httpSrv.Shutdown(ctx)
	}
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

// NewServer constructs a Server instance for handler use or testing.
func NewServer(gov *sheriff.Governor) *Server {
	return &Server{gov: gov}
}

// Handler returns the HTTP handler for the Command Center API and UI.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/assets/presets/", s.handlePresetImage)
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/orders", s.handleOrders)
	mux.HandleFunc("/api/preset", s.handlePreset)
	mux.HandleFunc("/api/standdown", s.handleStandDown)
	mux.HandleFunc("/api/enforce", s.handleEnforce)
	mux.HandleFunc("/api/focus", s.handleFocus)
	mux.HandleFunc("/api/elevate", s.handleElevate)
	mux.HandleFunc("/api/open-winsec", s.handleOpenWinSec)
	mux.HandleFunc("/api/quick-scan", s.handleQuickScan)
	mux.HandleFunc("/api/update-sigs", s.handleUpdateSigs)
	mux.HandleFunc("/api/service-install", s.handleServiceInstall)
	mux.HandleFunc("/api/service-uninstall", s.handleServiceUninstall)
	return mux
}

// URL returns the local loopback URL for the Command Center.
func (s *Server) URL() string {
	return s.url
}

// OpenWindow opens the Command Center in a native-feeling chromeless Edge/Chrome app window
// (falling back to the default browser), or focuses the existing window if one is already open.
func (s *Server) OpenWindow() {
	s.openMu.Lock()
	defer s.openMu.Unlock()

	if focusExistingCommandCenterWindow() {
		return
	}
	if !s.lastOpen.IsZero() && time.Since(s.lastOpen) < 1500*time.Millisecond {
		return
	}
	s.lastOpen = time.Now()

	args := []string{"--app=" + s.url, "--window-size=840,750"}
	if cacheDir, err := os.UserCacheDir(); err == nil && cacheDir != "" {
		profileDir := filepath.Join(cacheDir, "ShieldSheriff", "edge-app")
		args = append(args, "--user-data-dir="+profileDir)
	}

	edgePaths := []string{
		`C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`,
		`C:\Program Files\Microsoft\Edge\Application\msedge.exe`,
	}
	for _, p := range edgePaths {
		if _, err := os.Stat(p); err == nil {
			cmd := exec.Command(p, args...)
			if err := cmd.Start(); err == nil {
				return
			}
		}
	}
	_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", s.url).Start()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(dashboardHTML)
}

func (s *Server) handlePresetImage(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/assets/presets/")
	id = strings.TrimSuffix(id, ".jpg")
	b, ok := PresetImageBytes(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(b)
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	st, ord, sd, logs, cfgPath := s.gov.Snapshot()
	writeJSON(w, map[string]any{
		"version":    version.Info(),
		"status":     st,
		"orders":     ord,
		"standDown":  sd,
		"auditLog":   logs,
		"configPath": cfgPath,
		"presets":    defender.BuiltinPresets(),
	})
}

func (s *Server) handleOrders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var orders defender.StandingOrders
	if err := json.NewDecoder(r.Body).Decode(&orders); err != nil {
		writeJSON(w, map[string]any{"ok": false, "message": "Invalid JSON: " + err.Error()})
		return
	}
	res, err := s.gov.UpdateOrders(orders)
	msg := fmt.Sprintf("Saved & enforced (%d policies applied)", len(res.Applied))
	if !res.Success && len(res.Warnings) > 0 {
		msg = "Orders saved to disk (" + res.Warnings[0] + ")"
	} else if err != nil {
		msg = "Enforced with save note: " + err.Error()
	}
	writeJSON(w, map[string]any{"ok": res.Success, "message": msg, "result": res})
}

func (s *Server) handlePreset(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	for _, p := range defender.BuiltinPresets() {
		if p.ID == id {
			res, _ := s.gov.UpdateOrders(p.Orders)
			msg := "Activated preset: " + p.Name
			if !res.Success && len(res.Warnings) > 0 {
				msg += " (Saved; relaunch as Admin to enforce)"
			}
			writeJSON(w, map[string]any{"ok": true, "message": msg})
			return
		}
	}
	writeJSON(w, map[string]any{"ok": false, "message": "Unknown preset: " + id})
}

func (s *Server) handleStandDown(w http.ResponseWriter, r *http.Request) {
	mins, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	if mins <= 0 {
		res := s.gov.ResumeFromStandDown()
		writeJSON(w, map[string]any{"ok": res.Success, "message": "Deputy resumed normal duty"})
		return
	}
	dur := time.Duration(mins) * time.Minute
	res := s.gov.StartStandDown(dur, fmt.Sprintf("%dm Manual Pause", mins))
	msg := fmt.Sprintf("Deputy standing down for %d minutes", mins)
	if !res.Success && len(res.Warnings) > 0 {
		msg += " (" + res.Warnings[0] + ")"
	}
	writeJSON(w, map[string]any{"ok": res.Success, "message": msg})
}

func (s *Server) handleEnforce(w http.ResponseWriter, r *http.Request) {
	res := s.gov.EnforceNow()
	msg := fmt.Sprintf("Enforced %d Standing Order rules", len(res.Applied))
	if !res.Success && len(res.Warnings) > 0 {
		msg = res.Warnings[0]
	}
	writeJSON(w, map[string]any{"ok": res.Success, "message": msg, "result": res})
}

func (s *Server) handleFocus(w http.ResponseWriter, r *http.Request) {
	go s.OpenWindow()
	writeJSON(w, map[string]any{"ok": true, "message": "Focused Command Center"})
}

func (s *Server) handleElevate(w http.ResponseWriter, r *http.Request) {
	err := defender.RelaunchElevated([]string{"ui", "--replace"})
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "message": "Elevation cancelled or failed: " + err.Error()})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "message": "Launched elevated ShieldSheriff instance"})
	go func() {
		time.Sleep(600 * time.Millisecond)
		if s.onShutdown != nil {
			s.onShutdown()
			return
		}
		os.Exit(0)
	}()
}

func (s *Server) handleOpenWinSec(w http.ResponseWriter, r *http.Request) {
	_ = defender.OpenWindowsSecuritySettings()
	writeJSON(w, map[string]any{"ok": true, "message": "Opened Windows Security Threat Settings"})
}

func (s *Server) handleQuickScan(w http.ResponseWriter, r *http.Request) {
	go func() {
		_, _ = defender.RunQuickScan()
	}()
	writeJSON(w, map[string]any{"ok": true, "message": "Started background Quick Scan via MpCmdRun.exe"})
}

func (s *Server) handleUpdateSigs(w http.ResponseWriter, r *http.Request) {
	go func() {
		_, _ = defender.UpdateSignatures()
	}()
	writeJSON(w, map[string]any{"ok": true, "message": "Started signature update via MpCmdRun.exe"})
}

func (s *Server) handleServiceInstall(w http.ResponseWriter, r *http.Request) {
	msg, err := sheriff.InstallService()
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "message": "Service install failed (Admin required): " + strings.TrimSpace(msg+" "+err.Error())})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "message": msg})
}

func (s *Server) handleServiceUninstall(w http.ResponseWriter, r *http.Request) {
	msg, err := sheriff.UninstallService()
	if err != nil {
		writeJSON(w, map[string]any{"ok": false, "message": "Service removal failed: " + strings.TrimSpace(msg+" "+err.Error())})
		return
	}
	writeJSON(w, map[string]any{"ok": true, "message": "Removed ShieldSheriff SYSTEM service"})
}
