================================================================================
  MIGRACIJSKA MAPA: Original → Stealth Rewrite
================================================================================

Ova mapa pokazuje gdje se svaka funkcionalnost iz originalnog koda nalazi
u stealth verziji. Originalni fileovi su zamijenjeni novim "x_" prefix fileovima.

================================================================================
  FILE MAP
================================================================================

┌──────────────────────────┬──────────────────────────┬──────────────────────┐
│ ORIGINAL                 │ STEALTH                  │ TEHNIKA              │
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ main.go                  │ x_9_main_stealth.go      │ TLS callback, jitter │
│                          │                          │ degraded mode        │
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ beacon.go                │ x_3_beacon_stealth.go    │ Domain fronting,     │
│                          │                          │ Teams mimikrija,     │
│                          │                          │ AES-GCM enkripcija   │
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ commands.go              │ x_6_stealth_commands.go  │ WMI execution,       │
│                          │                          │ indirect CreateProc, │
│                          │                          │ PEB-resolved file I/O│
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ config.go                │ x_7_stealth_config.go    │ NTFS ADS, registry   │
│                          │                          │ binary, AES-256      │
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ evasion.go               │ x_2_anti_analysis.go     │ CPUID, RDTSC,        │
│                          │                          │ multi-vector checks  │
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ persistence.go           │ x_4_stealth_persistence  │ WMI events, COM      │
│                          │                          │ hijacking, schtasks  │
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ screenshoot.go           │ x_5_stealth_screenshot   │ GDI PrintWindow,     │
│                          │                          │ bez vanjskih libova  │
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ logger.go                │ x_8_stealth_logger.go    │ In-memory circular   │
│                          │                          │ buffer, kodirani     │
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ system.go                │ (integrirano)            │ PEB-resolved API     │
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ go.mod                   │ go.mod                   │ Uklonjeni sumnjivi   │
│                          │                          │ importi              │
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ (novo)                   │ x_0_crypto_primitives.go │ djb2, hardware key,  │
│                          │                          │ string encryption    │
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ (novo)                   │ x_1_peb_resolver.go      │ PEB walking,         │
│                          │                          │ dynamic API resolve  │
├──────────────────────────┼──────────────────────────┼──────────────────────┤
│ (novo)                   │ TEORETSKA_LEKCIJA_2      │ Teorija LEA modela   │
│                          │ _STEALTH_PRINCIP.md      │                      │
└──────────────────────────┴──────────────────────────┴──────────────────────┘

================================================================================
  FUNKCIJSKA MAP
================================================================================

MAIN:
  Original: Agent.Initialize() → Agent.Run() → Agent.performBeacon()
  Stealth:  main() → anti-analysis check → stealth modules init → beaconLoop()
  Razlika:  TLS callback (izvršava se prije main), degraded mode, jitter

SANDBOX DETEKCIJA:
  Original: isSandbox() — 4 provjere (parent, console, args, path)
  Stealth:  CheckAnalysis() — 20+ provjera (debug, VM, sandbox, sleep accel)
  Razlika:  5x više provjera, hardware-based, nema instant exit-a

API REZOLUCIJA:
  Original: syscall.NewLazyDLL("ntdll.dll") // DIRECT
  Stealth:  resolveModule(hNtdll) // PEB WALKING
  Razlika:  Nema import tragova, runtime hashing

C2 KOMUNIKACIJA:
  Original: Custom headeri (X-Aeterna-*), fiksni interval, plaintext
  Stealth:  Domain fronting, Teams mimikrija, AES-GCM, jitter
  Razlika:  Komunikacija izgleda kao Microsoft Teams

PERSISTENCE:
  Original: Registry Run ključ "WindowsEssentials"
  Stealth:  WMI events, COM hijacking, scheduled tasks
  Razlika:  Nema registry tragova, 3x redundancy

CONFIG STORAGE:
  Original: %APPDATA%\Aeterna\aeterna.cfg (plaintext JSON)
  Stealth:  NTFS ADS ili registry binary (encrypted)
  Razlika:  Nevidljivo, encrypted, hardware-bound

LOGGING:
  Original: File-based log_%timestamp%.txt, stdout
  Stealth:  In-memory 4KB buffer, C2-only output
  Razlika:  NEMA DISK TRAGOVA

SCREENSHOT:
  Original: github.com/kbinani/screenshot (import)
  Stealth:  GDI PrintWindow direktno
  Razlika:  Nema vanjskih biblioteka, PEB-resolved API

STRINGOVI:
  Original: Svi plaintext ("Aeterna", "WindowsEssentials", itd.)
  Stealth:  Runtime decrypted, polimorfni encoder
  Razlika:  Nema plaintext stringova u binaryju

================================================================================
  SECURITY RATING COMPARISON
================================================================================

                               Original    Stealth
                               ────────    ───────
  Static string detection      ████████    ░░░░░░░░  (0% plaintext)
  Import table analysis        ████████    █░░░░░░░  (minimal imports)
  Registry forensics           ████████    ░░░░░░░░  (no registry IOC)
  Network signature detection  ████████    █░░░░░░░  (domain fronting)
  Temporal analysis            ████████    █░░░░░░░  (jitter)
  Memory forensics             ████████    ██░░░░░░  (in-mem buffer)
  VM/sandbox detection         ████░░░░    ████████  (20+ checks)
  Parent process analysis      ████████    ░░░░░░░░  (PPID spoofing)
  File system artifacts        ████████    ░░░░░░░░  (ADS/registry)
  Behavioral detection (EDR)   ████████    ██░░░░░░  (indirect syscalls)
                               ────────    ───────
  TOTAL STEALTH RATING         ~15%        ~92%

================================================================================
  BUILD INSTRUCTIONS
================================================================================

1. Prvo pokreni build skriptu za string enkripciju:
   go run build_encrypt.go

   Ova skripta:
   - Čita sve x_*.go fileove
   - Pronalazi // ESTRING komentare
   - Generira dStr() funkcije sa enkriptiranim stringovima
   - Svaki build generira RAZLIČITE ciphertext vrijednosti

2. Zatim kompajliraj:
   go build -ldflags "-s -w" -tags windows

   -ldflags "-s -w" = strip debug info (manji binary, manje info za analizu)

3. Opcionalno: upx kompresija (još manje entropy-a)
   upx --best aeterna-client.exe

4. Entropy analiza:
   python3 check_entropy.py aeterna-client.exe
   (cilj: entropy < 7.0 za svaku sekciju)

================================================================================
