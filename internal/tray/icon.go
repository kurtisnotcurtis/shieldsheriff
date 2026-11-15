package tray

import (
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
	BadgeGold BadgeKind = iota
	BadgeStandDown
	BadgeWarning
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

	// Accent palette for state indication (0xAARRGGBB)
	var accR, accG, accB float64
	switch kind {
	case BadgeStandDown:
		// Cyan for Stand-Down (Paused)
		accR, accG, accB = 56, 189, 248
	case BadgeWarning:
		// Amber/Orange for Drift or Unprivileged Warning
		accR, accG, accB = 251, 146, 60
	default:
		// Classic Sheriff Gold
		accR, accG, accB = 250, 204, 21
	}

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

	// 5-point Sheriff star badge in lower shield
	var starPoly [10]pt2
	starCX, starCY := 16.0, 23.6
	for i := 0; i < 10; i++ {
		ang := -math.Pi/2 + float64(i)*(math.Pi/5.0)
		r := 3.2
		if i%2 == 1 {
			r = 1.4
		}
		starPoly[i] = pt2{starCX + r*math.Cos(ang), starCY + r*math.Sin(ang)}
	}

	// Stetson hat crown polygon
	hatCrown := []pt2{
		{11.4, 11.4},
		{12.6, 6.8},
		{16.0, 7.8},
		{19.4, 6.8},
		{20.6, 11.4},
	}

	// Sample color at subpixel (fx, fy)
	sampleColor := func(fx, fy float64) (r, g, b, a float64) {
		if !pointInPoly(fx, fy, shieldPoly) {
			return 0, 0, 0, 0
		}

		// Check shield outer rim
		minEdge := 99.0
		for i := 0; i < len(shieldPoly); i++ {
			aPt := shieldPoly[i]
			bPt := shieldPoly[(i+1)%len(shieldPoly)]
			d := distToSegment(fx, fy, aPt.x, aPt.y, bPt.x, bPt.y)
			if d < minEdge {
				minEdge = d
			}
		}
		if minEdge <= 1.25 {
			return accR, accG, accB, 1.0
		}

		// Base dark navy shield fill
		r, g, b = 15, 23, 42

		// Shoulders silhouette
		if fy >= 19.6 && fy <= 24.5 && math.Abs(fx-16.0) <= 6.2 {
			dx := (fx - 16.0) / 6.2
			dy := (fy - 24.5) / 4.9
			if dx*dx+dy*dy <= 1.0 {
				r, g, b = 30, 41, 59
			}
		}

		// Sheriff Star badge on chest
		if pointInPoly(fx, fy, starPoly[:]) {
			return accR, accG, accB, 1.0
		}

		// Head circle
		headDist := math.Hypot(fx-16.0, fy-15.2)
		if headDist <= 4.1 {
			if headDist >= 3.3 {
				r, g, b = 148, 163, 184
			} else {
				r, g, b = 15, 23, 42
			}
		}

		// Cyan Earmuffs (left & right of head)
		if (fx >= 9.8 && fx <= 12.1 && fy >= 13.0 && fy <= 17.4) ||
			(fx >= 19.9 && fx <= 22.2 && fy >= 13.0 && fy <= 17.4) {
			r, g, b = 56, 189, 248
		}

		// Cyan Blindfold across eyes
		if fx >= 11.7 && fx <= 20.3 && fy >= 13.7 && fy <= 16.1 {
			r, g, b = 56, 189, 248
		}

		// Stetson Hat brim ellipse & crown (drawn over forehead)
		brimDX := (fx - 16.0) / 7.8
		brimDY := (fy - 11.8) / 1.6
		brimD := brimDX*brimDX + brimDY*brimDY
		if brimD <= 1.0 {
			if brimD >= 0.52 {
				return accR, accG, accB, 1.0
			}
			return 30, 41, 59, 1.0
		}
		if pointInPoly(fx, fy, hatCrown) {
			minHat := 99.0
			for i := 0; i < len(hatCrown); i++ {
				aPt := hatCrown[i]
				bPt := hatCrown[(i+1)%len(hatCrown)]
				d := distToSegment(fx, fy, aPt.x, aPt.y, bPt.x, bPt.y)
				if d < minHat {
					minHat = d
				}
			}
			if minHat <= 0.85 {
				return accR, accG, accB, 1.0
			}
			return 30, 41, 59, 1.0
		}

		return r, g, b, 1.0
	}

	// Render with 3x3 supersampling
	const ss = 3
	const invSS2 = 1.0 / float64(ss*ss)
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var sumR, sumG, sumB, sumA float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					fx := float64(px) + (float64(sx)+0.5)/float64(ss)
					fy := float64(py) + (float64(sy)+0.5)/float64(ss)
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
