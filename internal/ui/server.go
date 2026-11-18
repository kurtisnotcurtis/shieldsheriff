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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jchv/go-webview2"
	"shieldsheriff/internal/defender"
	"shieldsheriff/internal/sheriff"
	"shieldsheriff/internal/version"
)

//go:embed dashboard.html
var dashboardHTML []byte

// Server hosts the local ShieldSheriff Command Center UI on 127.0.0.1.
type Server struct {
	gov            *sheriff.Governor
	addr           string
	url            string
	ln             net.Listener
	httpSrv        *http.Server
	onShutdown     func()
	onWindowClosed func()
	openMu         sync.Mutex
	lastOpen       time.Time
	activeWV       webview2.WebView
	activeHWND     uintptr
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
	s.openMu.Lock()
	s.onShutdown = fn
	s.openMu.Unlock()
}

// SetOnWindowClosed registers a callback invoked after an opened Command Center window closes.
func (s *Server) SetOnWindowClosed(fn func()) {
	s.openMu.Lock()
	s.onWindowClosed = fn
	s.openMu.Unlock()
}

func (s *Server) notifyWindowClosed() {
	s.openMu.Lock()
	fn := s.onWindowClosed
	s.openMu.Unlock()
	if fn != nil {
		fn()
	}
}

// Shutdown gracefully stops the Command Center HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.openMu.Lock()
	wv := s.activeWV
	s.openMu.Unlock()
	if wv != nil {
		wv.Terminate()
	}
	closeExistingCommandCenterWindow()
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
	mux.HandleFunc("/api/passive", s.handlePassiveMode)
	mux.HandleFunc("/api/enforce", s.handleEnforce)
	mux.HandleFunc("/api/focus", s.handleFocus)
	mux.HandleFunc("/api/elevate", s.handleElevate)
	mux.HandleFunc("/api/open-winsec", s.handleOpenWinSec)
	mux.HandleFunc("/api/quick-scan", s.handleQuickScan)
	mux.HandleFunc("/api/update-sigs", s.handleUpdateSigs)
	mux.HandleFunc("/api/service-install", s.handleServiceInstall)
	mux.HandleFunc("/api/service-uninstall", s.handleServiceUninstall)
	mux.HandleFunc("/api/check-updates", s.handleCheckUpdates)
	return mux
}

// URL returns the local loopback URL for the Command Center.
func (s *Server) URL() string {
	return s.url
}

// OpenWindow opens the Command Center in a native Windows 11 WebView2 window with Mica chrome
// (falling back to Edge --app / default browser if WebView2 is unavailable), or focuses the existing window.
func (s *Server) OpenWindow() {
	s.openMu.Lock()
	if s.activeHWND != 0 {
		hwnd := s.activeHWND
		s.openMu.Unlock()
		focusWindowHandle(hwnd)
		return
	}
	if focusExistingCommandCenterWindow() {
		s.openMu.Unlock()
		return
	}
	if !s.lastOpen.IsZero() && time.Since(s.lastOpen) < 1500*time.Millisecond {
		s.openMu.Unlock()
		return
	}
	s.lastOpen = time.Now()
	url := s.url
	s.openMu.Unlock()

	var profileDir string
	if cacheDir, err := os.UserCacheDir(); err == nil && cacheDir != "" {
		profileDir = filepath.Join(cacheDir, "ShieldSheriff", "webview2")
	}

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		w := webview2.NewWithOptions(webview2.WebViewOptions{
			AutoFocus: true,
			DataPath:  profileDir,
			WindowOptions: webview2.WindowOptions{
				Title:  "ShieldSheriff",
				Width:  1120,
				Height: 780,
				Center: true,
			},
		})
		if w == nil {
			s.openEdgeFallback(url)
			return
		}

		hwnd := uintptr(w.Window())
		applyWindows11Chrome(hwnd, ReadWindowsTheme().DarkMode)

		s.openMu.Lock()
		s.activeWV = w
		s.activeHWND = hwnd
		s.openMu.Unlock()

		w.Navigate(url)
		w.Run()
		w.Destroy()

		s.openMu.Lock()
		if s.activeWV == w {
			s.activeWV = nil
			s.activeHWND = 0
		}
		s.openMu.Unlock()
		s.notifyWindowClosed()
	}()
}

func (s *Server) openEdgeFallback(url string) {
	args := []string{"--app=" + url, "--window-size=1120,780"}
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
				_ = cmd.Wait()
				s.notifyWindowClosed()
				return
			}
		}
	}
	_ = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url).Start()
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
		"theme":      ReadWindowsTheme(),
		"firstRun":   s.gov.IsFirstRun(),
		"status":     st,
		"orders":     ord,
		"standDown":  sd,
		"update":     s.gov.GetUpdateInfo(),
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
	msg := fmt.Sprintf("Applied %d setting(s)", len(res.Applied))
	if !res.Success && len(res.Warnings) > 0 {
		msg = "Settings saved (" + res.Warnings[0] + ")"
	} else if err != nil {
		msg = "Applied with save note: " + err.Error()
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

func (s *Server) handlePassiveMode(w http.ResponseWriter, r *http.Request) {
	res := s.gov.EnterPassiveMode()
	msg := "Entered Passive Mode (policies reverted)"
	if !res.Success && len(res.Warnings) > 0 {
		msg = res.Warnings[0]
	}
	writeJSON(w, map[string]any{"ok": res.Success, "message": msg})
}

func (s *Server) handleStandDown(w http.ResponseWriter, r *http.Request) {
	mins, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	if mins <= 0 {
		res := s.gov.ResumeFromStandDown()
		writeJSON(w, map[string]any{"ok": res.Success, "message": "Protection resumed"})
		return
	}
	dur := time.Duration(mins) * time.Minute
	res := s.gov.StartStandDown(dur, fmt.Sprintf("%dm Pause", mins))
	msg := fmt.Sprintf("Protection paused for %d minutes", mins)
	if !res.Success && len(res.Warnings) > 0 {
		msg += " (" + res.Warnings[0] + ")"
	}
	writeJSON(w, map[string]any{"ok": res.Success, "message": msg})
}

func (s *Server) handleEnforce(w http.ResponseWriter, r *http.Request) {
	res := s.gov.EnforceNow()
	msg := fmt.Sprintf("Applied %d policy rules", len(res.Applied))
	if !res.Success && len(res.Warnings) > 0 {
		msg = res.Warnings[0]
	}
	writeJSON(w, map[string]any{"ok": res.Success, "message": msg, "result": res})
}

func (s *Server) handleFocus(w http.ResponseWriter, r *http.Request) {
	go s.OpenWindow()
	writeJSON(w, map[string]any{"ok": true, "message": "Focused ShieldSheriff window"})
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
		s.openMu.Lock()
		fn := s.onShutdown
		s.openMu.Unlock()
		if fn != nil {
			fn()
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

func (s *Server) handleCheckUpdates(w http.ResponseWriter, r *http.Request) {
	info := s.gov.CheckForUpdates()
	msg := fmt.Sprintf("Up to date (v%s)", info.CurrentVersion)
	if info.Error != "" {
		msg = "Update check failed: " + info.Error
	} else if info.Available {
		msg = fmt.Sprintf("Update available: v%s", info.LatestVersion)
	}
	writeJSON(w, map[string]any{"ok": info.Error == "", "message": msg, "update": info})
}
