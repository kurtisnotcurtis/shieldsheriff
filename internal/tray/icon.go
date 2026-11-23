//go:build windows

package tray

import (
	"image"
	"image/color"
	"math"
	"syscall"
	"unsafe"
)

var (
	modGdi32               = syscall.NewLazyDLL("gdi32.dll")
	modUser32              = syscall.NewLazyDLL("user32.dll")
	procCreateDIBSection   = modGdi32.NewProc("CreateDIBSection")
	procCreateBitmap       = modGdi32.NewProc("CreateBitmap")
	procDeleteObject       = modGdi32.NewProc("DeleteObject")
	procCreateIconIndirect = modUser32.NewProc("CreateIconIndirect")
)

type BadgeKind int

const (
	BadgePassive BadgeKind = iota
	BadgePause
	BadgePresetOnDemand
	BadgePresetDev
	BadgePresetQuiet
	BadgePresetFull
	BadgePresetCustom
	BadgeBrand
)

type bitmapInfoHeader struct {
	Size          uint32
	Width         int32
	Height        int32
	Planes        uint16
	BitCount      uint16
	Compression   uint32
	SizeImage     uint32
	XPelsPerMeter int32
	YPelsPerMeter int32
	ClrUsed       uint32
	ClrImportant  uint32
}

type iconInfo struct {
	IsIcon   int32
	XHotspot uint32
	YHotspot uint32
	HbmMask  uintptr
	HbmColor uintptr
}

type pt2 struct{ x, y float64 }

func pointInPoly(x, y float64, poly []pt2) bool {
	inside := false
	j := len(poly) - 1
	for i := 0; i < len(poly); i++ {
		yi, yj := poly[i].y, poly[j].y
		xi, xj := poly[i].x, poly[j].x
		if ((yi > y) != (yj > y)) && (x < (xj-xi)*(y-yi)/(yj-yi)+xi) {
			inside = !inside
		}
		j = i
	}
	return inside
}

func distToSegment(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	lenSq := dx*dx + dy*dy
	if lenSq == 0 {
		return math.Hypot(px-ax, py-ay)
	}
	t := ((px-ax)*dx + (py-ay)*dy) / lenSq
	if t < 0 {
		t = 0
	} else if t > 1 {
		t = 1
	}
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

// CreateSheriffBadgeIcon generates a 32x32 32-bit ARGB Win32 HICON depicting the
// ShieldSheriff emblem (outer shield, Stetson hat, blindfold, earmuffs, and star badge).
func CreateSheriffBadgeIcon(kind BadgeKind) uintptr {
	const size = 32
	hdr := bitmapInfoHeader{
		Size:     uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		Width:    size,
		Height:   -size, // top-down DIB
		Planes:   1,
		BitCount: 32,
	}

	var bitsPtr *uint32
	hbmColor, _, _ := procCreateDIBSection.Call(
		0,
		uintptr(unsafe.Pointer(&hdr)),
		0,
		uintptr(unsafe.Pointer(&bitsPtr)),
		0,
		0,
	)
	if hbmColor == 0 || bitsPtr == nil {
		return 0
	}
	defer procDeleteObject.Call(hbmColor)

	pixels := unsafe.Slice(bitsPtr, size*size)
	renderSheriffBadgePixels(kind, size, pixels)

	hbmMask, _, _ := procCreateBitmap.Call(size, size, 1, 1, 0)
	defer procDeleteObject.Call(hbmMask)

	ii := iconInfo{
		IsIcon:   1,
		HbmMask:  hbmMask,
		HbmColor: hbmColor,
	}
	hIcon, _, _ := procCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	return hIcon
}

// RenderBadgeNRGBA renders the specified badge kind into a straight-alpha NRGBA image of size x size.
func RenderBadgeNRGBA(kind BadgeKind, size int) *image.NRGBA {
	pixels := make([]uint32, size*size)
	renderSheriffBadgePixels(kind, size, pixels)

	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			p := pixels[y*size+x]
			a := uint8(p >> 24)
			if a == 0 {
				continue
			}
			// Un-premultiply ARGB into straight NRGBA
			af := float64(a) / 255.0
			r := uint8(math.Min(255, float64(uint8(p>>16))/af))
			g := uint8(math.Min(255, float64(uint8(p>>8))/af))
			b := uint8(math.Min(255, float64(uint8(p))/af))
			img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: a})
		}
	}
	return img
}

func renderSheriffBadgePixels(kind BadgeKind, size int, pixels []uint32) {
	// Outer shield polygon (32x32 space)
	shieldPoly := []pt2{
		{16.0, 2.2},
		{27.6, 6.0},
		{27.6, 17.2},
		{23.8, 24.4},
		{16.0, 29.8},
		{8.2, 24.4},
		{4.4, 17.2},
		{4.4, 6.0},
	}

	// Centered tilted cowboy hat inset in shield (for BadgeBrand)
	brandHatCrown := []pt2{
		{11.6, 17.0},
		{12.4, 11.4},
		{15.8, 10.6},
		{19.8, 10.6},
		{21.0, 16.4},
	}
	brandHatBrim := []pt2{
		{8.4, 18.8},
		{9.6, 15.6},
		{14.5, 15.2},
		{21.2, 15.0},
		{23.8, 16.4},
		{23.4, 18.4},
		{18.2, 19.6},
		{13.0, 21.6},
		{9.2, 21.4},
	}

	shieldEdgeDist := func(fx, fy float64) float64 {
		minEdge := 99.0
		for i := 0; i < len(shieldPoly); i++ {
			aPt := shieldPoly[i]
			bPt := shieldPoly[(i+1)%len(shieldPoly)]
			d := distToSegment(fx, fy, aPt.x, aPt.y, bPt.x, bPt.y)
			if d < minEdge {
				minEdge = d
			}
		}
		return minEdge
	}

	// Sample color at subpixel (fx, fy)
	sampleColor := func(fx, fy float64) (r, g, b, a float64) {
		switch kind {
		case BadgePassive:
			// Hollow shield outline (passthrough / not enforcing)
			if !pointInPoly(fx, fy, shieldPoly) {
				return 0, 0, 0, 0
			}
			d := shieldEdgeDist(fx, fy)
			if d <= 2.3 {
				return 148, 163, 184, 1.0
			}
			return 0, 0, 0, 0

		case BadgePause:
			// Solid amber shield with crisp dark pause bars (||)
			if !pointInPoly(fx, fy, shieldPoly) {
				return 0, 0, 0, 0
			}
			if (fx >= 11.4 && fx <= 14.2 && fy >= 10.2 && fy <= 21.6) ||
				(fx >= 17.8 && fx <= 20.6 && fy >= 10.2 && fy <= 21.6) {
				return 15, 23, 42, 1.0
			}
			return 251, 146, 60, 1.0

		case BadgePresetOnDemand:
			// Solid coral-red shield with horizontal minus bar (-)
			if !pointInPoly(fx, fy, shieldPoly) {
				return 0, 0, 0, 0
			}
			if fx >= 9.6 && fx <= 22.4 && fy >= 14.3 && fy <= 17.7 {
				return 15, 23, 42, 1.0
			}
			return 248, 113, 113, 1.0

		case BadgePresetDev:
			// Solid sky-blue shield with < > code brackets
			if !pointInPoly(fx, fy, shieldPoly) {
				return 0, 0, 0, 0
			}
			dl1 := distToSegment(fx, fy, 13.0, 11.0, 8.6, 15.8)
			dl2 := distToSegment(fx, fy, 8.6, 15.8, 13.0, 20.6)
			dr1 := distToSegment(fx, fy, 19.0, 11.0, 23.4, 15.8)
			dr2 := distToSegment(fx, fy, 23.4, 15.8, 19.0, 20.6)
			if dl1 <= 1.55 || dl2 <= 1.55 || dr1 <= 1.55 || dr2 <= 1.55 {
				return 15, 23, 42, 1.0
			}
			return 96, 205, 255, 1.0

		case BadgePresetQuiet:
			// Solid sky-blue shield
			if !pointInPoly(fx, fy, shieldPoly) {
				return 0, 0, 0, 0
			}
			return 56, 189, 248, 1.0

		case BadgePresetFull:
			// Solid emerald-green shield with dark checkmark
			if !pointInPoly(fx, fy, shieldPoly) {
				return 0, 0, 0, 0
			}
			dc1 := distToSegment(fx, fy, 10.2, 16.2, 14.2, 20.2)
			dc2 := distToSegment(fx, fy, 14.2, 20.2, 22.2, 11.8)
			if dc1 <= 1.75 || dc2 <= 1.75 {
				return 15, 23, 42, 1.0
			}
			return 74, 222, 128, 1.0

		case BadgePresetCustom:
			// Rounded dark badge with blue control bars
			if fx < 3.0 || fx > 29.0 || fy < 3.0 || fy > 29.0 {
				return 0, 0, 0, 0
			}
			if (fy >= 9.0 && fy <= 11.4 && fx >= 7.0 && fx <= 25.0) ||
				(fy >= 14.8 && fy <= 17.2 && fx >= 7.0 && fx <= 20.0) ||
				(fy >= 20.6 && fy <= 23.0 && fx >= 7.0 && fx <= 22.5) {
				return 96, 165, 250, 1.0
			}
			return 30, 41, 59, 1.0
		}

		// BadgeBrand: Clean Windows-style dark shield with gold rim and tilted hat with negative crease lines
		accR, accG, accB := 250.0, 204.0, 21.0
		if !pointInPoly(fx, fy, shieldPoly) {
			return 0, 0, 0, 0
		}
		if shieldEdgeDist(fx, fy) <= 1.6 {
			return accR, accG, accB, 1.0
		}
		// Rotate point by +7 deg around (16, 16.5) so hat tilts -7 deg
		const ang = 0.122
		dx, dy := fx-16.0, fy-16.5
		rx := 16.0 + dx*math.Cos(ang) - dy*math.Sin(ang)
		ry := 16.5 + dx*math.Sin(ang) + dy*math.Cos(ang)

		if pointInPoly(rx, ry, brandHatCrown) || pointInPoly(rx, ry, brandHatBrim) {
			// Negative-space lines: brim-crown seam, top crease, and side pinch
			if distToSegment(rx, ry, 11.4, 16.8, 21.2, 15.8) <= 0.55 ||
				distToSegment(rx, ry, 13.2, 12.0, 19.2, 11.0) <= 0.52 ||
				distToSegment(rx, ry, 17.2, 12.4, 16.4, 13.9) <= 0.48 ||
				distToSegment(rx, ry, 16.4, 13.9, 18.2, 14.6) <= 0.48 {
				return 15, 23, 42, 1.0
			}
			return accR, accG, accB, 1.0
		}
		return 15, 23, 42, 1.0
	}

	// Render with 3x3 supersampling
	const ss = 3
	const invSS2 = 1.0 / float64(ss*ss)
	scale := 32.0 / float64(size)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var sumR, sumG, sumB, sumA float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					fx := (float64(px) + (float64(sx)+0.5)/float64(ss)) * scale
					fy := (float64(py) + (float64(sy)+0.5)/float64(ss)) * scale
					sr, sg, sb, sa := sampleColor(fx, fy)
					sumR += sr * sa
					sumG += sg * sa
					sumB += sb * sa
					sumA += sa
				}
			}
			cov := sumA * invSS2
			if cov == 0 {
				pixels[py*size+px] = 0
				continue
			}
			// Premultiplied ARGB
			alpha := uint32(math.Min(255, math.Max(0, cov*255.0)))
			ri := uint32(math.Min(255, math.Max(0, sumR*invSS2)))
			gi := uint32(math.Min(255, math.Max(0, sumG*invSS2)))
			bi := uint32(math.Min(255, math.Max(0, sumB*invSS2)))
			pixels[py*size+px] = (alpha << 24) | (ri << 16) | (gi << 8) | bi
		}
	}
}
