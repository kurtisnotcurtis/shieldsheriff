//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/sys/windows"
	"shieldsheriff/internal/defender"
	"shieldsheriff/internal/sheriff"
)

// acquireSingleInstance creates a named Windows mutex to ensure only one interactive
// ShieldSheriff Dashboard / tray instance runs per user session.
func acquireSingleInstance(name string) (release func(), alreadyRunning bool, err error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, false, err
	}
	handle, err := windows.CreateMutex(nil, false, namePtr)
	if handle == 0 {
		return nil, false, err
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		_ = windows.CloseHandle(handle)
		return nil, true, nil
	}
	return func() {
		_ = windows.CloseHandle(handle)
	}, false, nil
}

// focusExistingInstance discovers the running instance's actual listening port and focus token
// from focus.json and asks it to bring its Dashboard window to the foreground.
func focusExistingInstance() bool {
	ep, err := sheriff.ReadFocusEndpoint()
	if err != nil {
		return false
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/api/focus", ep.Port), nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-ShieldSheriff-Token", ep.FocusToken)
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type remoteAPIResponse struct {
	OK      bool                   `json:"ok"`
	Message string                 `json:"message"`
	Result  defender.EnforceResult `json:"result"`
}

// sendToRunningGovernor forwards an elevated CLI mutation directly to a running elevated tray
// instance via its admin-restricted control.json endpoint so both share one live Governor.
func sendToRunningGovernor(path string, payload any) (remoteAPIResponse, bool) {
	var out remoteAPIResponse
	if !defender.IsProcessElevated() {
		return out, false
	}
	ep, err := sheriff.ReadControlEndpoint()
	if err != nil || !ep.Elevated {
		return out, false
	}

	var bodyReader *bytes.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return out, false
		}
		bodyReader = bytes.NewReader(b)
	} else {
		bodyReader = bytes.NewReader(nil)
	}

	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d%s", ep.Port, path), bodyReader)
	if err != nil {
		return out, false
	}
	req.Header.Set("X-ShieldSheriff-Token", ep.Token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return out, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, false
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return out, false
	}
	return out, true
}
