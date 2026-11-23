//go:build windows

package ui

import (
	"fmt"
	"syscall"
	"unsafe"

	"shieldsheriff/internal/defender"
)

var procSystemParametersInfoW = modUser32.NewProc("SystemParametersInfoW")

const spiGetNonClientMetrics = 0x0029

type logFontW struct {
	LfHeight         int32
	LfWidth          int32
	LfEscapement     int32
	LfOrientation    int32
	LfWeight         int32
	LfItalic         byte
	LfUnderline      byte
	LfStrikeOut      byte
	LfCharSet        byte
	LfOutPrecision   byte
	LfClipPrecision  byte
	LfQuality        byte
	LfPitchAndFamily byte
	LfFaceName       [32]uint16
}

type nonClientMetricsW struct {
	CbSize             uint32
	IBorderWidth       int32
	IScrollWidth       int32
	IScrollHeight      int32
	ICaptionWidth      int32
	ICaptionHeight     int32
	LfCaptionFont      logFontW
	ISmCaptionWidth    int32
	ISmCaptionHeight   int32
	LfSmCaptionFont    logFontW
	IMenuWidth         int32
	IMenuHeight        int32
	LfMenuFont         logFontW
	LfStatusFont       logFontW
	LfMessageFont      logFontW
	IPaddedBorderWidth int32
}

// ThemeInfo describes the current Windows 11 light/dark mode, accent color, and system UI font.
type ThemeInfo struct {
	DarkMode    bool   `json:"darkMode"`
	AccentColor string `json:"accentColor"`
	AccentFG    string `json:"accentFg"`
	SystemFont  string `json:"systemFont"`
}

func readSystemMessageFont() string {
	var ncm nonClientMetricsW
	ncm.CbSize = uint32(unsafe.Sizeof(ncm))
	r1, _, _ := procSystemParametersInfoW.Call(
		spiGetNonClientMetrics,
		uintptr(ncm.CbSize),
		uintptr(unsafe.Pointer(&ncm)),
		0,
	)
	if r1 != 0 {
		if name := syscall.UTF16ToString(ncm.LfMessageFont.LfFaceName[:]); name != "" {
			return name
		}
	}
	return "Segoe UI Variable Text"
}

// ReadWindowsTheme inspects HKCU Windows 11 personalization, DWM accent, and system message font.
func ReadWindowsTheme() ThemeInfo {
	darkMode := true
	if v, ok := defender.ReadHKCUDword(`SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize`, "AppsUseLightTheme"); ok {
		darkMode = (v == 0)
	}

	// Default Windows 11 Fluent accents
	accent := "#60cdff"
	fg := "#000000"
	if !darkMode {
		accent = "#0067c0"
		fg = "#ffffff"
	}

	if raw, ok := defender.ReadHKCUDword(`SOFTWARE\Microsoft\Windows\DWM`, "AccentColor"); ok {
		r := float64(raw & 0xFF)
		g := float64((raw >> 8) & 0xFF)
		b := float64((raw >> 16) & 0xFF)

		if darkMode {
			// Lighten slightly for crisp contrast on #202020 / #2b2b2b
			r = r + (255-r)*0.32
			g = g + (255-g)*0.32
			b = b + (255-b)*0.32
		} else {
			// Ensure readable contrast on #ffffff
			lum := 0.299*r + 0.587*g + 0.114*b
			if lum > 165 {
				r *= 0.72
				g *= 0.72
				b *= 0.72
			}
		}

		ri := uint8(r)
		gi := uint8(g)
		bi := uint8(b)
		accent = fmt.Sprintf("#%02x%02x%02x", ri, gi, bi)
		lum := 0.299*float64(ri) + 0.587*float64(gi) + 0.114*float64(bi)
		if lum > 150 {
			fg = "#000000"
		} else {
			fg = "#ffffff"
		}
	}

	return ThemeInfo{
		DarkMode:    darkMode,
		AccentColor: accent,
		AccentFG:    fg,
		SystemFont:  readSystemMessageFont(),
	}
}
