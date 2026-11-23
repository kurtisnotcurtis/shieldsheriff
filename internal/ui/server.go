//go:build windows

package ui

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
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

const (
	tokenHeaderName = "X-ShieldSheriff-Token"
	maxJSONBodySize = 64 << 10 // 64 KiB
)

// Server hosts the local authenticated ShieldSheriff Dashboard UI and control API on 127.0.0.1.
type Server struct {
	gov            *sheriff.Governor
	addr           string
	port           int
	url            string
	apiToken       string
	focusToken     string
	ln             net.Listener
	httpSrv        *http.Server
	onShutdown     func()
	onWindowClosed func()
	openMu         sync.Mutex
	lastOpen       time.Time
	published      bool
	activeWV       webview2.WebView
	activeHWND     uintptr
}

func generateToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// StartServer starts the local loopback Dashboard HTTP server with per-launch random tokens
// and publishes runtime discovery files for elevated CLI coordination and window focus handoff.
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

	tcpAddr := ln.Addr().(*net.TCPAddr)
	s := &Server{
		gov:        gov,
		addr:       ln.Addr().String(),
		port:       tcpAddr.Port,
		url:        "http://" + ln.Addr().String(),
		apiToken:   generateToken(),
		focusToken: generateToken(),
		ln:         ln,
	}
	s.httpSrv = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			_ = ln.Close()
		}
	}()
	return s, nil
}

// PublishRuntimeEndpoints writes focus.json (and admin-only control.json when elevated)
// so other local ShieldSheriff processes can focus the window or coordinate CLI mutations.
func (s *Server) PublishRuntimeEndpoints() {
	if s.port <= 0 {
		return
	}
	s.openMu.Lock()
	s.published = true
	s.openMu.Unlock()

	pid := os.Getpid()
	_ = sheriff.WriteFocusEndpoint(sheriff.FocusEndpoint{
		PID:        pid,
		Port:       s.port,
		FocusToken: s.focusToken,
	})
	if defender.IsProcessElevated() {
		_ = sheriff.WriteControlEndpoint(sheriff.ControlEndpoint{
			PID:      pid,
			Port:     s.port,
			Token:    s.apiToken,
			Elevated: true,
		})
	}
}

// NewServer constructs an in-memory Server instance for unit testing.
func NewServer(gov *sheriff.Governor) *Server {
	return &Server{
		gov:        gov,
		apiToken:   generateToken(),
		focusToken: generateToken(),
	}
}

// URL returns the local loopback URL for the Dashboard.
func (s *Server) URL() string { return s.url }

// Port returns the listening TCP port (0 if constructed via NewServer).
func (s *Server) Port() int { return s.port }

// APIToken returns the per-launch API token required in X-ShieldSheriff-Token.
func (s *Server) APIToken() string { return s.apiToken }

// FocusToken returns the per-launch focus-only token accepted by POST /api/focus.
func (s *Server) FocusToken() string { return s.focusToken }

// SetOnShutdown registers a callback used when the server initiates a process shutdown (e.g. UAC relaunch).
func (s *Server) SetOnShutdown(fn func()) {
	s.openMu.Lock()
	s.onShutdown = fn
	s.openMu.Unlock()
}

// SetOnWindowClosed registers a callback invoked after an opened Dashboard window closes.
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

// Shutdown gracefully stops the Dashboard window, removes runtime discovery files, and closes the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.openMu.Lock()
	published := s.published
	wv := s.activeWV
	hwnd := s.activeHWND
	s.openMu.Unlock()

	if published {
		pid := os.Getpid()
		sheriff.RemoveControlEndpoint(pid)
		sheriff.RemoveFocusEndpoint(pid)
	}
	if wv != nil {
		wv.Terminate()
	}
	if hwnd != 0 {
		closeWindowHandle(hwnd)
	}
	if s.httpSrv != nil {
		return s.httpSrv.Shutdown(ctx)
	}
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

// Handler returns the HTTP handler for the Dashboard UI and authenticated local API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/state", s.requireAPI(http.MethodGet, false, s.handleState))
	mux.HandleFunc("/api/config", s.requireAPI(http.MethodPost, false, s.handleConfig))
	mux.HandleFunc("/api/pause", s.requireAPI(http.MethodPost, false, s.handlePause))
	mux.HandleFunc("/api/passive", s.requireAPI(http.MethodPost, false, s.handlePassiveMode))
	mux.HandleFunc("/api/focus", s.requireAPI(http.MethodPost, true, s.handleFocus))
	mux.HandleFunc("/api/elevate", s.requireAPI(http.MethodPost, false, s.handleElevate))
	mux.HandleFunc("/api/open-winsec", s.requireAPI(http.MethodPost, false, s.handleOpenWinSec))
	mux.HandleFunc("/api/quick-scan", s.requireAPI(http.MethodPost, false, s.handleQuickScan))
	mux.HandleFunc("/api/update-sigs", s.requireAPI(http.MethodPost, false, s.handleUpdateSigs))
	mux.HandleFunc("/api/check-updates", s.requireAPI(http.MethodPost, false, s.handleCheckUpdates))
	return mux
}

func constantTimeTokenEqual(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *Server) isAllowedHost(host string) bool {
	if host == "" {
		return false
	}
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		h = host
		p = ""
	}
	h = strings.ToLower(h)
	if h != "127.0.0.1" && h != "localhost" {
		return false
	}
	if s.port > 0 && p != strconv.Itoa(s.port) {
		return false
	}
	return true
}

func (s *Server) isAllowedOrigin(origin string) bool {
	if origin == "" {
		return true // non-browser clients (e.g. elevated CLI) omit Origin; still require token
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" {
		return false
	}
	return s.isAllowedHost(u.Host)
}

// requireAPI enforces Host, Origin, per-launch token, and HTTP method checks on all /api/* routes.
func (s *Server) requireAPI(method string, allowFocusToken bool, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		if r.Method != method {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.port > 0 && !s.isAllowedHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" && !s.isAllowedOrigin(origin) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		if sfs := strings.ToLower(r.Header.Get("Sec-Fetch-Site")); sfs != "" && sfs != "same-origin" && sfs != "none" {
			http.Error(w, "forbidden cross-site request", http.StatusForbidden)
			return
		}

		tok := r.Header.Get(tokenHeaderName)
		authorized := constantTimeTokenEqual(tok, s.apiToken) || (allowFocusToken && constantTimeTokenEqual(tok, s.focusToken))
		if !authorized {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// OpenWindow opens the Dashboard in a native Windows 11 WebView2 window with Mica chrome,
// or focuses this server's already-open window handle.
func (s *Server) OpenWindow() {
	s.openMu.Lock()
	if s.activeHWND != 0 {
		hwnd := s.activeHWND
		s.openMu.Unlock()
		focusWindowHandle(hwnd)
		return
	}
	if !s.lastOpen.IsZero() && time.Since(s.lastOpen) < 1500*time.Millisecond {
		s.openMu.Unlock()
		return
	}
	s.lastOpen = time.Now()
	targetURL := s.url
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
			fmt.Fprintln(os.Stderr, "WebView2 runtime unavailable; cannot open Dashboard window.")
			s.notifyWindowClosed()
			return
		}

		hwnd := uintptr(w.Window())
		applyWindows11Chrome(hwnd, ReadWindowsTheme().DarkMode)

		s.openMu.Lock()
		s.activeWV = w
		s.activeHWND = hwnd
		s.openMu.Unlock()

		w.Navigate(targetURL)
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.port > 0 && !s.isAllowedHost(r.Host) {
		http.Error(w, "forbidden host", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	rendered := bytes.Replace(dashboardHTML, []byte("__SHIELDSHERIFF_API_TOKEN__"), []byte(s.apiToken), 1)
	_, _ = w.Write(rendered)
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	st, cfg, logs, cfgPath := s.gov.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"version":     version.Info(),
		"theme":       ReadWindowsTheme(),
		"status":      st,
		"config":      cfg,
		"configError": s.gov.ConfigError(),
		"update":      s.gov.GetUpdateInfo(),
		"auditLog":    logs,
		"configPath":  cfgPath,
		"presets":     defender.BuiltinPresets(),
	})
}

// configUpdateRequest uses pointer fields so omitted keys preserve current values
// instead of silently zero-valuing protection settings to OFF.
type configUpdateRequest struct {
	Mode        *defender.Mode    `json:"mode"`
	Policy      *policyPatch      `json:"policy"`
	Preferences *preferencesPatch `json:"preferences"`
}

type policyPatch struct {
	PresetID              *string   `json:"presetId"`
	RealtimeProtection    *bool     `json:"realtimeProtection"`
	BehaviorMonitoring    *bool     `json:"behaviorMonitoring"`
	IOAVProtection        *bool     `json:"ioavProtection"`
	ScriptScanning        *bool     `json:"scriptScanning"`
	NetworkProtection     *uint32   `json:"networkProtection"`
	CloudProtection       *uint32   `json:"cloudProtection"`
	SampleSubmission      *uint32   `json:"sampleSubmission"`
	SuppressAllNags       *bool     `json:"suppressAllNags"`
	SuppressEnhancedNags  *bool     `json:"suppressEnhancedNags"`
	MuteWindowsSecSystray *bool     `json:"muteWindowsSecSystray"`
	AutoPauseProcesses    *[]string `json:"autoPauseProcesses"`
}

type preferencesPatch struct {
	AutoHeal            *bool `json:"autoHeal"`
	DriftCheckSeconds   *int  `json:"driftCheckSeconds"`
	StartupEnabled      *bool `json:"startupEnabled"`
	CheckUpdatesOnStart *bool `json:"checkUpdatesOnStart"`
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req configUpdateRequest
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "Invalid JSON: " + err.Error()})
		return
	}
	if req.Mode == nil && req.Policy == nil && req.Preferences == nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "Empty configuration payload"})
		return
	}

	_, cur, _, _ := s.gov.Snapshot()
	mode := cur.Mode
	if req.Mode != nil {
		mode = *req.Mode
	}
	if !mode.Valid() {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": fmt.Sprintf("Invalid mode %q", mode)})
		return
	}

	policy := cur.Policy.Clone()
	if p := req.Policy; p != nil {
		if p.PresetID != nil {
			policy.PresetID = strings.TrimSpace(*p.PresetID)
		}
		if p.RealtimeProtection != nil {
			policy.RealtimeProtection = *p.RealtimeProtection
		}
		if p.BehaviorMonitoring != nil {
			policy.BehaviorMonitoring = *p.BehaviorMonitoring
		}
		if p.IOAVProtection != nil {
			policy.IOAVProtection = *p.IOAVProtection
		}
		if p.ScriptScanning != nil {
			policy.ScriptScanning = *p.ScriptScanning
		}
		if p.NetworkProtection != nil {
			policy.NetworkProtection = *p.NetworkProtection
		}
		if p.CloudProtection != nil {
			policy.CloudProtection = *p.CloudProtection
		}
		if p.SampleSubmission != nil {
			policy.SampleSubmission = *p.SampleSubmission
		}
		if p.SuppressAllNags != nil {
			policy.SuppressAllNags = *p.SuppressAllNags
		}
		if p.SuppressEnhancedNags != nil {
			policy.SuppressEnhancedNags = *p.SuppressEnhancedNags
		}
		if p.MuteWindowsSecSystray != nil {
			policy.MuteWindowsSecSystray = *p.MuteWindowsSecSystray
		}
		if p.AutoPauseProcesses != nil {
			policy.AutoPauseProcesses = *p.AutoPauseProcesses
		}
	}
	if err := policy.Validate(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": err.Error()})
		return
	}

	prefs := cur.Preferences
	if pr := req.Preferences; pr != nil {
		if pr.AutoHeal != nil {
			prefs.AutoHeal = *pr.AutoHeal
		}
		if pr.DriftCheckSeconds != nil {
			prefs.DriftCheckSeconds = *pr.DriftCheckSeconds
		}
		if pr.StartupEnabled != nil {
			prefs.StartupEnabled = *pr.StartupEnabled
		}
		if pr.CheckUpdatesOnStart != nil {
			prefs.CheckUpdatesOnStart = *pr.CheckUpdatesOnStart
		}
	}
	prefs.Normalize()

	res, err := s.gov.UpdateConfig(mode, policy, prefs)
	msg := fmt.Sprintf("Applied %d setting(s)", len(res.Applied))
	if !res.Success && len(res.Warnings) > 0 {
		msg = "Settings saved (" + res.Warnings[0] + ")"
	} else if err != nil {
		msg = "Applied with save error: " + err.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": res.Success && err == nil, "message": msg, "result": res})
}

func (s *Server) handlePassiveMode(w http.ResponseWriter, r *http.Request) {
	res, err := s.gov.EnterPassiveMode()
	msg := "Entered Passive Mode (reverted ShieldSheriff settings)"
	if err != nil {
		msg = "Save error: " + err.Error()
	} else if !res.Success && len(res.Warnings) > 0 {
		msg = res.Warnings[0]
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": res.Success && err == nil, "message": msg, "result": res})
}

type pauseRequest struct {
	Minutes int    `json:"minutes"`
	Reason  string `json:"reason"`
}

func (s *Server) handlePause(w http.ResponseWriter, r *http.Request) {
	var req pauseRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodySize)
	if r.Body != nil {
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "Invalid JSON: " + err.Error()})
			return
		}
	}
	if q := r.URL.Query().Get("minutes"); q != "" && req.Minutes == 0 {
		m, err := strconv.Atoi(q)
		if err != nil || m < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "message": "Invalid minutes parameter"})
			return
		}
		req.Minutes = m
	}

	if req.Minutes <= 0 {
		res, err := s.gov.ResumePause()
		msg := "Protection resumed"
		if err != nil {
			msg = err.Error()
		} else if !res.Success && len(res.Warnings) > 0 {
			msg = res.Warnings[0]
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": res.Success && err == nil, "message": msg, "result": res})
		return
	}

	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = fmt.Sprintf("%dm Pause", req.Minutes)
	}
	dur := time.Duration(req.Minutes) * time.Minute
	res, err := s.gov.StartPause(dur, reason)
	msg := fmt.Sprintf("Protection paused for %d minutes", req.Minutes)
	if err != nil {
		msg = err.Error()
	} else if !res.Success && len(res.Warnings) > 0 {
		msg += " (" + res.Warnings[0] + ")"
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": res.Success && err == nil, "message": msg, "result": res})
}

func (s *Server) handleFocus(w http.ResponseWriter, r *http.Request) {
	go s.OpenWindow()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Focused ShieldSheriff window"})
}

func (s *Server) handleElevate(w http.ResponseWriter, r *http.Request) {
	err := defender.RelaunchElevated([]string{"ui", "--replace"})
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Elevation cancelled or failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Launched elevated ShieldSheriff instance"})
	go func() {
		time.Sleep(300 * time.Millisecond)
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
	if err := defender.OpenWindowsSecuritySettings(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "message": "Failed to open Windows Security: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Opened Windows Security Threat Settings"})
}

func (s *Server) handleQuickScan(w http.ResponseWriter, r *http.Request) {
	go func() {
		_, _ = defender.RunQuickScan()
	}()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Started background Quick Scan via MpCmdRun.exe"})
}

func (s *Server) handleUpdateSigs(w http.ResponseWriter, r *http.Request) {
	go func() {
		_, _ = defender.UpdateSignatures()
	}()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Started signature update via MpCmdRun.exe"})
}

func (s *Server) handleCheckUpdates(w http.ResponseWriter, r *http.Request) {
	info := s.gov.CheckForUpdates()
	msg := fmt.Sprintf("Up to date (v%s)", info.CurrentVersion)
	if info.Error != "" {
		msg = "Update check failed: " + info.Error
	} else if info.Available {
		msg = fmt.Sprintf("Update available: v%s", info.LatestVersion)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": info.Error == "", "message": msg, "update": info})
}
