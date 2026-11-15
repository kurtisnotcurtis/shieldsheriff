package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"shieldsheriff/internal/sheriff"
)

func TestServerEndpoints(t *testing.T) {
	gov := sheriff.NewGovernor()
	srv := NewServer(gov)
	h := srv.Handler()

	// 1. Index HTML
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK || !strings.Contains(rec1.Body.String(), "ShieldSheriff") {
		t.Fatalf("expected 200 OK with ShieldSheriff HTML, got %d", rec1.Code)
	}

	// 2. GET /api/state
	req2 := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	var payload map[string]any
	if err := json.NewDecoder(rec2.Body).Decode(&payload); err != nil {
		t.Fatalf("decode /api/state failed: %v", err)
	}
	if payload["status"] == nil || payload["orders"] == nil {
		t.Fatalf("missing status or orders in /api/state response")
	}

	// 3. POST /api/standdown?minutes=15
	req3 := httptest.NewRequest(http.MethodPost, "/api/standdown?minutes=15", nil)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	var sdOut map[string]any
	_ = json.NewDecoder(rec3.Body).Decode(&sdOut)
	if msg, _ := sdOut["message"].(string); !strings.Contains(msg, "15 minutes") {
		t.Fatalf("unexpected standdown message: %v", sdOut)
	}

	// 4. Resume
	req4 := httptest.NewRequest(http.MethodPost, "/api/standdown?minutes=0", nil)
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, req4)

	// 5. Embedded Sheriff preset artwork
	for _, id := range []string{"quiet-guardian", "dev-workstation", "on-demand-only", "full-shield-no-nag"} {
		reqImg := httptest.NewRequest(http.MethodGet, "/assets/presets/"+id+".jpg", nil)
		recImg := httptest.NewRecorder()
		h.ServeHTTP(recImg, reqImg)
		if recImg.Code != http.StatusOK || recImg.Header().Get("Content-Type") != "image/jpeg" || recImg.Body.Len() < 1000 {
			t.Fatalf("expected valid JPEG for preset %s, got code=%d len=%d", id, recImg.Code, recImg.Body.Len())
		}
	}

	reqMissing := httptest.NewRequest(http.MethodGet, "/assets/presets/unknown.jpg", nil)
	recMissing := httptest.NewRecorder()
	h.ServeHTTP(recMissing, reqMissing)
	if recMissing.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown preset image, got %d", recMissing.Code)
	}
}
