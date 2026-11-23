//go:build windows

package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"shieldsheriff/internal/defender"
	"shieldsheriff/internal/sheriff"
)

type noopBackend struct{ elevated bool }

func (n noopBackend) IsElevated() bool                                          { return n.elevated }
func (n noopBackend) ReadDword(defender.RegRoot, string, string) (uint32, bool) { return 0, false }
func (n noopBackend) ReadString(defender.RegRoot, string, string) (string, defender.RegValueKind, bool) {
	return "", 0, false
}
func (n noopBackend) WriteDword(defender.RegRoot, string, string, uint32) error { return nil }
func (n noopBackend) WriteString(defender.RegRoot, string, string, string, defender.RegValueKind) error {
	return nil
}
func (n noopBackend) DeleteValue(defender.RegRoot, string, string) error { return nil }
func (n noopBackend) RunCommand(context.Context, string, ...string) (string, error) {
	return "ok", nil
}
func (n noopBackend) FileExists(string) bool { return false }

func newTestGovernor(t *testing.T) *sheriff.Governor {
	t.Helper()
	return sheriff.NewGovernorWithDeps(sheriff.GovernorDeps{
		Backend:            noopBackend{elevated: true},
		ConfigPath:         filepath.Join(t.TempDir(), "config.json"),
		FindWatchedProcess: func([]string) string { return "" },
		IsStartupEnabled:   func() bool { return false },
		SetStartup:         func(bool) error { return nil },
	})
}

func TestServerAuthAndEndpoints(t *testing.T) {
	gov := newTestGovernor(t)
	srv := NewServer(gov)
	h := srv.Handler()

	// 1. Index HTML injects per-launch API token & security headers
	reqIdx := httptest.NewRequest(http.MethodGet, "/", nil)
	recIdx := httptest.NewRecorder()
	h.ServeHTTP(recIdx, reqIdx)
	if recIdx.Code != http.StatusOK || !strings.Contains(recIdx.Body.String(), srv.APIToken()) {
		t.Fatalf("expected 200 OK with injected API token, got %d", recIdx.Code)
	}
	if recIdx.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("expected X-Frame-Options: DENY header")
	}

	// 2. Unauthenticated API calls MUST fail with 401
	for _, tc := range [][2]string{
		{http.MethodGet, "/api/state"},
		{http.MethodPost, "/api/config"},
		{http.MethodPost, "/api/pause"},
		{http.MethodPost, "/api/passive"},
		{http.MethodPost, "/api/focus"},
	} {
		req := httptest.NewRequest(tc[0], tc[1], nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s without token: got %d, want 401", tc[0], tc[1], rec.Code)
		}
	}

	// 3. Wrong HTTP methods MUST fail with 405
	for _, tc := range [][2]string{
		{http.MethodPost, "/api/state"},
		{http.MethodGet, "/api/config"},
		{http.MethodGet, "/api/pause"},
		{http.MethodGet, "/api/passive"},
		{http.MethodGet, "/api/elevate"},
	} {
		req := httptest.NewRequest(tc[0], tc[1], nil)
		req.Header.Set(tokenHeaderName, srv.APIToken())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: got %d, want 405", tc[0], tc[1], rec.Code)
		}
	}

	// 4. Cross-site Origin / Sec-Fetch-Site MUST fail with 403
	reqXSite := httptest.NewRequest(http.MethodPost, "/api/passive", nil)
	reqXSite.Header.Set(tokenHeaderName, srv.APIToken())
	reqXSite.Header.Set("Origin", "https://evil.example")
	recXSite := httptest.NewRecorder()
	h.ServeHTTP(recXSite, reqXSite)
	if recXSite.Code != http.StatusForbidden {
		t.Fatalf("cross-origin request: got %d, want 403", recXSite.Code)
	}

	// 5. Focus token works ONLY on /api/focus, NOT on /api/state or /api/config
	reqFocus := httptest.NewRequest(http.MethodPost, "/api/focus", nil)
	reqFocus.Header.Set(tokenHeaderName, srv.FocusToken())
	recFocus := httptest.NewRecorder()
	h.ServeHTTP(recFocus, reqFocus)
	if recFocus.Code != http.StatusOK {
		t.Fatalf("/api/focus with focus token: got %d, want 200", recFocus.Code)
	}
	reqFocusAbuse := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	reqFocusAbuse.Header.Set(tokenHeaderName, srv.FocusToken())
	recFocusAbuse := httptest.NewRecorder()
	h.ServeHTTP(recFocusAbuse, reqFocusAbuse)
	if recFocusAbuse.Code != http.StatusUnauthorized {
		t.Fatalf("/api/state with focus token: got %d, want 401", recFocusAbuse.Code)
	}

	// 6. Authenticated GET /api/state
	reqState := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	reqState.Header.Set(tokenHeaderName, srv.APIToken())
	recState := httptest.NewRecorder()
	h.ServeHTTP(recState, reqState)
	var statePayload map[string]any
	if err := json.NewDecoder(recState.Body).Decode(&statePayload); err != nil {
		t.Fatalf("decode /api/state failed: %v", err)
	}
	if statePayload["status"] == nil || statePayload["config"] == nil || statePayload["theme"] == nil {
		t.Fatalf("missing expected keys in /api/state: %v", statePayload)
	}

	// 7. POST /api/config rejects invalid enums and preserves omitted fields
	reqBad := httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewBufferString(`{"policy":{"cloudProtection":99}}`))
	reqBad.Header.Set(tokenHeaderName, srv.APIToken())
	recBad := httptest.NewRecorder()
	h.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid cloudProtection, got %d", recBad.Code)
	}

	// Activate with Local Protection first
	reqActive := httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewBufferString(`{"mode":"active","policy":{"presetId":"local-protection","realtimeProtection":true,"behaviorMonitoring":true}}`))
	reqActive.Header.Set(tokenHeaderName, srv.APIToken())
	recActive := httptest.NewRecorder()
	h.ServeHTTP(recActive, reqActive)
	if recActive.Code != http.StatusOK {
		t.Fatalf("activate config failed: %d %s", recActive.Code, recActive.Body.String())
	}

	// Partial update omitting realtimeProtection MUST preserve realtimeProtection=true (never zero to OFF!)
	reqPatch := httptest.NewRequest(http.MethodPost, "/api/config", bytes.NewBufferString(`{"preferences":{"driftCheckSeconds":60}}`))
	reqPatch.Header.Set(tokenHeaderName, srv.APIToken())
	recPatch := httptest.NewRecorder()
	h.ServeHTTP(recPatch, reqPatch)
	if recPatch.Code != http.StatusOK {
		t.Fatalf("patch config failed: %d", recPatch.Code)
	}
	_, cfgAfterPatch, _, _ := gov.Snapshot()
	if !cfgAfterPatch.Policy.RealtimeProtection || cfgAfterPatch.Preferences.DriftCheckSeconds != 60 {
		t.Fatalf("partial config update clobbered fields: %+v", cfgAfterPatch)
	}

	// 8. Authenticated Pause & Resume
	reqPause := httptest.NewRequest(http.MethodPost, "/api/pause", bytes.NewBufferString(`{"minutes":15}`))
	reqPause.Header.Set(tokenHeaderName, srv.APIToken())
	recPause := httptest.NewRecorder()
	h.ServeHTTP(recPause, reqPause)
	var pauseOut map[string]any
	_ = json.NewDecoder(recPause.Body).Decode(&pauseOut)
	if msg, _ := pauseOut["message"].(string); !strings.Contains(msg, "15 minutes") {
		t.Fatalf("unexpected pause message: %v", pauseOut)
	}

	reqResume := httptest.NewRequest(http.MethodPost, "/api/pause", bytes.NewBufferString(`{"minutes":0}`))
	reqResume.Header.Set(tokenHeaderName, srv.APIToken())
	recResume := httptest.NewRecorder()
	h.ServeHTTP(recResume, reqResume)
	if recResume.Code != http.StatusOK {
		t.Fatalf("resume failed: %d", recResume.Code)
	}

	// 9. Deleted dead routes return 404
	for _, dead := range []string{"/api/preset", "/api/enforce", "/api/service-install", "/assets/presets/local-protection.jpg"} {
		req := httptest.NewRequest(http.MethodGet, dead, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for removed route %s, got %d", dead, rec.Code)
		}
	}
}

func TestServerStartAndShutdown(t *testing.T) {
	gov := newTestGovernor(t)
	srv, err := StartServer(gov, 0)
	if err != nil {
		t.Fatalf("StartServer failed: %v", err)
	}
	if srv.URL() == "" || srv.Port() == 0 || srv.ln == nil || srv.httpSrv == nil {
		t.Fatalf("expected initialized server, url=%q port=%d", srv.URL(), srv.Port())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	if _, err := srv.ln.Accept(); err == nil {
		t.Fatalf("expected listener to be closed after Shutdown")
	}
}

func TestServerWindowClosedCallback(t *testing.T) {
	gov := newTestGovernor(t)
	srv := NewServer(gov)

	called := make(chan struct{}, 1)
	srv.SetOnWindowClosed(func() {
		select {
		case called <- struct{}{}:
		default:
		}
	})

	srv.notifyWindowClosed()

	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatalf("expected SetOnWindowClosed callback to fire")
	}
}
