// Package qopanza is a Go client for the Qopanza API.
//
// It covers the crypto endpoints (keys, encrypt, decrypt, sign, verify),
// the AI analysis endpoint, and the scanner/posture endpoints that make
// the API useful from CI. Account signup, billing and support are
// dashboard concerns and are not part of this SDK — the same scoping the
// Python, TypeScript and Java SDKs use.
//
// Get an API key by signing up first; it is shown exactly once:
//
//	resp, _ := http.Post("http://localhost:8000/v1/accounts", "application/json",
//	    strings.NewReader(`{"email":"you@example.com","password":"a-real-password"}`))
//
// This client holds a secret API key, so it belongs server-side.
//
// Byte handling is deliberately []byte at the API boundary rather than
// base64 strings: base64 is a wire-format detail, and making callers
// encode it themselves is how a plaintext ends up double-encoded in
// production.
package qopanza

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL points at a local development server.
const DefaultBaseURL = "http://localhost:8000"

// APIError is returned for any non-2xx response. It keeps the status code
// separate from the message so callers can branch on it — a 409 from a
// revoked key needs different handling from a 429 from a rate limit.
type APIError struct {
	StatusCode int
	Detail     string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("qopanza: [%d] %s", e.StatusCode, e.Detail)
}

// Client talks to the Qopanza API. The zero value is not usable;
// construct one with New.
type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient supplies a custom *http.Client — for proxies, custom
// TLS configuration, or a test transport.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithTimeout sets the request timeout. Ignored if WithHTTPClient is also
// given, since that client carries its own.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.httpClient.Timeout = d }
}

// New builds a Client. baseURL may be empty for DefaultBaseURL.
func New(baseURL, apiKey string, opts ...Option) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	c := &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/v1"+path, reader)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("calling the Qopanza API: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		// The API returns {"detail": "..."} for its own errors; anything
		// else (a proxy's HTML error page, say) is surfaced raw rather
		// than swallowed, because "unknown error" helps nobody debug.
		var envelope struct {
			Detail json.RawMessage `json:"detail"`
		}
		detail := strings.TrimSpace(string(payload))
		if json.Unmarshal(payload, &envelope) == nil && len(envelope.Detail) > 0 {
			var text string
			if json.Unmarshal(envelope.Detail, &text) == nil {
				detail = text
			} else {
				detail = string(envelope.Detail)
			}
		}
		return &APIError{StatusCode: resp.StatusCode, Detail: detail}
	}

	if out == nil || len(payload) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

// ---- Keys ------------------------------------------------------------------

// Key is a PQC keypair held by the platform (or, when ClientManaged is
// true, a public key registered from elsewhere).
type Key struct {
	ID            string `json:"id"`
	Purpose       string `json:"purpose"`
	Algorithm     string `json:"algorithm"`
	Backend       string `json:"backend"`
	PublicKey     string `json:"public_key"`
	CreatedAt     string `json:"created_at"`
	Label         string `json:"label"`
	ExpiresAt     string `json:"expires_at"`
	ClientManaged bool   `json:"client_managed"`
	Version       int    `json:"version"`
}

// CreateKey generates a keypair. purpose is "kem", "signature", or
// "hybrid_kem".
func (c *Client) CreateKey(ctx context.Context, purpose, label string) (*Key, error) {
	var key Key
	body := map[string]any{"purpose": purpose}
	if label != "" {
		body["label"] = label
	}
	if err := c.do(ctx, http.MethodPost, "/keys", body, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// GetKey fetches a key's metadata and public key.
func (c *Client) GetKey(ctx context.Context, keyID string) (*Key, error) {
	var key Key
	if err := c.do(ctx, http.MethodGet, "/keys/"+url.PathEscape(keyID), nil, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

// ---- Encrypt / decrypt ------------------------------------------------------

// Encrypted is everything needed to decrypt. Pass it straight back to
// Decrypt rather than reassembling the fields by hand.
type Encrypted struct {
	KeyID             string `json:"key_id"`
	CiphertextKEM     string `json:"ciphertext_kem"`
	CiphertextPayload string `json:"ciphertext_payload"`
	Nonce             string `json:"nonce"`
	Backend           string `json:"backend"`
	UsedManagedKey    bool   `json:"used_managed_key"`
}

// Encrypt seals plaintext. Pass an empty keyID for the one-line path, in
// which case the platform provisions and reuses a managed key for the
// account and reports which one it used in the result.
func (c *Client) Encrypt(ctx context.Context, keyID string, plaintext []byte) (*Encrypted, error) {
	body := map[string]any{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}
	if keyID != "" {
		body["key_id"] = keyID
	}
	var out Encrypted
	if err := c.do(ctx, http.MethodPost, "/encrypt", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Decrypt opens what Encrypt sealed.
func (c *Client) Decrypt(ctx context.Context, enc *Encrypted) ([]byte, error) {
	body := map[string]any{
		"key_id":             enc.KeyID,
		"ciphertext_kem":     enc.CiphertextKEM,
		"ciphertext_payload": enc.CiphertextPayload,
		"nonce":              enc.Nonce,
	}
	var out struct {
		Plaintext string `json:"plaintext"`
	}
	if err := c.do(ctx, http.MethodPost, "/decrypt", body, &out); err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(out.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("decoding plaintext: %w", err)
	}
	return decoded, nil
}

// ---- Sign / verify ----------------------------------------------------------

// Signature is a detached PQC signature, base64-encoded.
type Signature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
	Backend   string `json:"backend"`
}

// Sign produces a signature over message with a "signature"-purpose key.
func (c *Client) Sign(ctx context.Context, keyID string, message []byte) (*Signature, error) {
	body := map[string]any{
		"key_id":  keyID,
		"message": base64.StdEncoding.EncodeToString(message),
	}
	var out Signature
	if err := c.do(ctx, http.MethodPost, "/sign", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Verify checks a signature. A false result means the signature did not
// verify; a non-nil error means the check could not be performed. Those
// are different outcomes and must not be conflated — treating an
// unreachable API as "invalid signature" is how a verification step
// silently becomes a no-op.
func (c *Client) Verify(ctx context.Context, keyID string, message []byte, signature string) (bool, error) {
	body := map[string]any{
		"key_id":    keyID,
		"message":   base64.StdEncoding.EncodeToString(message),
		"signature": signature,
	}
	var out struct {
		Valid bool `json:"valid"`
	}
	if err := c.do(ctx, http.MethodPost, "/verify", body, &out); err != nil {
		return false, err
	}
	return out.Valid, nil
}

// ---- AI analysis ------------------------------------------------------------

// Finding is one item from the analysis rules layer.
type Finding struct {
	Severity       string `json:"severity"`
	RuleID         string `json:"rule_id"`
	Title          string `json:"title"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation"`
}

// Analysis is the result of an /analyze call. GeneratedBy is "rules" or
// "rules+ai" — the rules layer is deterministic and always runs.
type Analysis struct {
	Findings    []Finding `json:"findings"`
	Summary     string    `json:"summary"`
	GeneratedBy string    `json:"generated_by"`
}

// Analyze runs the security analysis over a caller-supplied context.
func (c *Client) Analyze(ctx context.Context, context_ map[string]any) (*Analysis, error) {
	var out Analysis
	if err := c.do(ctx, http.MethodPost, "/analyze", map[string]any{"context": context_}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ---- Scanner ----------------------------------------------------------------

// ScanRun is one discovery run. A failed run has a nil RiskScore rather
// than a zero one, because a scan that could not run must never be read
// as a clean result.
type ScanRun struct {
	ID                string `json:"id"`
	SourceType        string `json:"source_type"`
	Target            string `json:"target"`
	Status            string `json:"status"`
	Error             string `json:"error"`
	AssetsFound       int    `json:"assets_found"`
	QuantumVulnerable int    `json:"quantum_vulnerable"`
	QuantumSafe       int    `json:"quantum_safe"`
	RiskScore         *int   `json:"risk_score"`
	CreatedAt         string `json:"created_at"`
	CompletedAt       string `json:"completed_at"`
}

// CryptoAsset is one piece of cryptography the scanner found.
type CryptoAsset struct {
	ID             string `json:"id"`
	Algorithm      string `json:"algorithm"`
	KeySize        *int   `json:"key_size"`
	Location       string `json:"location"`
	LineNumber     *int   `json:"line_number"`
	QuantumStatus  string `json:"quantum_status"`
	Severity       string `json:"severity"`
	Recommendation string `json:"recommendation"`
}

// ScanCode scans submitted source or manifest text. Nothing is fetched —
// only what you pass is scanned.
func (c *Client) ScanCode(ctx context.Context, filename, content string) (*ScanRun, error) {
	var out ScanRun
	body := map[string]any{"filename": filename, "content": content}
	if err := c.do(ctx, http.MethodPost, "/scan/code", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ScanTLS probes a live endpoint and records what it actually negotiates,
// including its certificate's key algorithm.
func (c *Client) ScanTLS(ctx context.Context, host string, port int) (*ScanRun, error) {
	if port == 0 {
		port = 443
	}
	var out ScanRun
	body := map[string]any{"host": host, "port": port}
	if err := c.do(ctx, http.MethodPost, "/scan/tls", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ScanAssets lists the findings from a scan.
func (c *Client) ScanAssets(ctx context.Context, scanID string) ([]CryptoAsset, error) {
	var out []CryptoAsset
	if err := c.do(ctx, http.MethodGet, "/scans/"+url.PathEscape(scanID)+"/assets", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- Posture / inventory -----------------------------------------------------

// Posture is the account's overall quantum-security position. Score runs
// 0-100 where higher is better, so it moves opposite to QuantumRisk.
type Posture struct {
	Score              int            `json:"score"`
	QuantumRisk        string         `json:"quantum_risk"`
	TotalAssets        int            `json:"total_assets"`
	VulnerableAssets   int            `json:"vulnerable_assets"`
	PQCAssets          int            `json:"pqc_assets"`
	UnknownAssets      int            `json:"unknown_assets"`
	CategoryScores     map[string]int `json:"category_scores"`
	TopRisks           []string       `json:"top_risks"`
	RecommendedActions []string       `json:"recommended_actions"`
	LastScanAt         *string        `json:"last_scan_at"`
}

// InventoryEntry is one algorithm and how much of it exists.
type InventoryEntry struct {
	Algorithm     string `json:"algorithm"`
	Count         int    `json:"count"`
	QuantumStatus string `json:"quantum_status"`
}

// Inventory is the cryptographic estate as currently known.
type Inventory struct {
	TotalAssets       int              `json:"total_assets"`
	QuantumVulnerable int              `json:"quantum_vulnerable"`
	QuantumSafe       int              `json:"quantum_safe"`
	Unknown           int              `json:"unknown"`
	ByAlgorithm       []InventoryEntry `json:"by_algorithm"`
	ScansRun          int              `json:"scans_run"`
}

// SecurityPosture fetches the account's quantum risk score and drivers.
//
// A score of 100 on an account that has never scanned anything means "no
// vulnerable cryptography found", which on an empty inventory is an
// absence of evidence rather than evidence of safety — check LastScanAt
// before treating the number as an assessment.
func (c *Client) SecurityPosture(ctx context.Context) (*Posture, error) {
	var out Posture
	if err := c.do(ctx, http.MethodGet, "/security/posture", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CryptoInventory lists every algorithm found across the estate.
func (c *Client) CryptoInventory(ctx context.Context) (*Inventory, error) {
	var out Inventory
	if err := c.do(ctx, http.MethodGet, "/inventory", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
