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

// CreateSheriffBadgeIcon generates a 32x32 32-bit ARGB Win32 HICON depicting a 6-pointed Sheriff's Star badge.
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

	// Palette selection (0xAARRGGBB)
	var mainR, mainG, mainB float64
	var rimR, rimG, rimB float64
	switch kind {
	case BadgeStandDown:
		// Cool Cyan/Ice badge for Stand-Down (Paused)
		mainR, mainG, mainB = 56, 189, 248
		rimR, rimG, rimB = 14, 116, 144
	case BadgeWarning:
		// Amber/Orange badge for Drift or Tamper Warning
		mainR, mainG, mainB = 251, 146, 60
		rimR, rimG, rimB = 194, 65, 12
	default:
		// Classic Sheriff Gold Star
		mainR, mainG, mainB = 250, 204, 21
		rimR, rimG, rimB = 180, 115, 9
	}

	cx, cy := 15.5, 15.5
	outerR := 12.2
	innerR := 6.3
	finialR := 1.55

	// Precompute 12 vertices of the 6-pointed star + 6 tip centers for classic sheriff ball finials
	type pt struct{ x, y float64 }
	var poly [12]pt
	var tips [6]pt
	for i := 0; i < 12; i++ {
		ang := -math.Pi/2 + float64(i)*(math.Pi/6.0)
		r := outerR
		if i%2 == 1 {
			r = innerR
		}
		px := cx + r*math.Cos(ang)
		py := cy + r*math.Sin(ang)
		poly[i] = pt{px, py}
		if i%2 == 0 {
			tips[i/2] = pt{
				x: cx + (outerR+0.7)*math.Cos(ang),
				y: cy + (outerR+0.7)*math.Sin(ang),
			}
		}
	}

	inStar := func(x, y float64) bool {
		// Point-in-polygon for 12-vertex star
		inside := false
		j := 11
		for i := 0; i < 12; i++ {
			yi, yj := poly[i].y, poly[j].y
			xi, xj := poly[i].x, poly[j].x
			if ((yi > y) != (yj > y)) && (x < (xj-xi)*(y-yi)/(yj-yi)+xi) {
				inside = !inside
			}
			j = i
		}
		if inside {
			return true
		}
		// Check ball finials at the 6 star tips
		for _, t := range tips {
			dx, dy := x-t.x, y-t.y
			if dx*dx+dy*dy <= finialR*finialR {
				return true
			}
		}
		return false
	}

	// Render with 2x2 supersampling
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var covStar, covBg float64
			for sy := 0; sy < 2; sy++ {
				for sx := 0; sx < 2; sx++ {
					fx := float64(px) + 0.25 + 0.5*float64(sx)
					fy := float64(py) + 0.25 + 0.5*float64(sy)
					dx, dy := fx-cx, fy-cy
					dist := math.Sqrt(dx*dx + dy*dy)
					if dist <= 15.0 {
						covBg += 0.25
					}
					if inStar(fx, fy) {
						covStar += 0.25
					}
				}
			}

			if covBg == 0 && covStar == 0 {
				pixels[py*size+px] = 0
				continue
			}

			dx, dy := float64(px)-cx, float64(py)-cy
			dist := math.Sqrt(dx*dx + dy*dy)

			// Dark slate circular badge backing so the star pops on both light and dark taskbars
			bgR, bgG, bgB := 15.0, 23.0, 42.0
			if dist > 13.5 {
				// Subtle outer ring
				bgR, bgG, bgB = rimR*0.6, rimG*0.6, rimB*0.6
			}

			var r, g, b, a float64
			a = math.Max(covBg, covStar) * 255.0

			if covStar > 0 {
				// Slight metallic bevel shading from top-left to bottom-right
				shade := 1.0 + (-dx-dy)*0.015
				sr := math.Min(255, math.Max(0, mainR*shade))
				sg := math.Min(255, math.Max(0, mainG*shade))
				sb := math.Min(255, math.Max(0, mainB*shade))

				// Center engraved ring on the sheriff star
				if math.Abs(dist-3.2) < 0.75 {
					sr, sg, sb = rimR, rimG, rimB
				}

				r = sr*covStar + bgR*(1.0-covStar)
				g = sg*covStar + bgG*(1.0-covStar)
				b = sb*covStar + bgB*(1.0-covStar)
			} else {
				r, g, b = bgR, bgG, bgB
			}

			// Premultiply alpha
			alpha := uint32(math.Min(255, math.Max(0, a)))
			af := float64(alpha) / 255.0
			ri := uint32(math.Min(255, math.Max(0, r*af)))
			gi := uint32(math.Min(255, math.Max(0, g*af)))
			bi := uint32(math.Min(255, math.Max(0, b*af)))

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
