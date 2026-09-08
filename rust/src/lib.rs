//! Rust client for the Qopanza API.
//!
//! Covers the crypto endpoints (keys, encrypt, decrypt, sign, verify), the
//! AI analysis endpoint, and the scanner/posture endpoints that make the
//! API useful from CI. Account signup, billing and support are dashboard
//! concerns and are not part of this SDK — the same scoping the Python,
//! Go, TypeScript and Java SDKs use.
//!
//! ```no_run
//! use qopanza::Client;
//!
//! # async fn example() -> Result<(), qopanza::Error> {
//! let client = Client::new("http://localhost:8000", "qsk_...");
//!
//! // One-line encryption: no key management at all.
//! let sealed = client.encrypt(None, b"customer sensitive information").await?;
//! let opened = client.decrypt(&sealed).await?;
//! assert_eq!(opened, b"customer sensitive information");
//! # Ok(())
//! # }
//! ```
//!
//! Byte handling is `&[u8]` / `Vec<u8>` at the API boundary rather than
//! base64 strings: base64 is a wire-format detail, and making callers
//! encode it themselves is how a plaintext ends up double-encoded in
//! production.
//!
//! This client holds a secret API key, so it belongs server-side.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

pub const DEFAULT_BASE_URL: &str = "http://localhost:8000";

/// Everything that can go wrong.
///
/// `Api` keeps the status code separate from the message so callers can
/// branch on it — a 409 from a revoked key needs different handling from
/// a 429 from a rate limit.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("qopanza: [{status}] {detail}")]
    Api { status: u16, detail: String },

    #[error("transport: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("decoding response: {0}")]
    Decode(String),
}

// ---- Wire types -------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct Key {
    pub id: String,
    pub purpose: String,
    pub algorithm: String,
    pub backend: String,
    pub public_key: String,
    pub created_at: String,
    pub label: Option<String>,
    pub expires_at: Option<String>,
    #[serde(default)]
    pub client_managed: bool,
    #[serde(default = "one")]
    pub version: u32,
}

fn one() -> u32 {
    1
}

/// Everything needed to decrypt. Pass it straight back to [`Client::decrypt`]
/// rather than reassembling the fields by hand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Encrypted {
    pub key_id: String,
    pub ciphertext_kem: String,
    pub ciphertext_payload: String,
    pub nonce: String,
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub used_managed_key: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Signature {
    pub key_id: String,
    pub signature: String,
    #[serde(default)]
    pub backend: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Finding {
    pub severity: String,
    pub rule_id: String,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Analysis {
    pub findings: Vec<Finding>,
    pub summary: String,
    pub generated_by: String,
}

/// One discovery run.
///
/// `risk_score` is `None` for a failed scan rather than zero, because a
/// scan that could not run must never be read as a clean result.
#[derive(Debug, Clone, Deserialize)]
pub struct ScanRun {
    pub id: String,
    pub source_type: String,
    pub target: String,
    pub status: String,
    pub error: Option<String>,
    pub assets_found: i64,
    pub quantum_vulnerable: i64,
    pub quantum_safe: i64,
    pub risk_score: Option<i64>,
    pub created_at: String,
    pub completed_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CryptoAsset {
    pub id: String,
    pub algorithm: String,
    pub key_size: Option<i64>,
    pub location: String,
    pub line_number: Option<i64>,
    pub quantum_status: String,
    pub severity: String,
    pub recommendation: Option<String>,
}

/// The account's overall quantum-security position.
///
/// `score` runs 0-100 where higher is better, so it moves opposite to
/// `quantum_risk`. A score of 100 with `last_scan_at: None` means "no
/// vulnerable cryptography found" on an empty inventory — an absence of
/// evidence, not evidence of safety.
#[derive(Debug, Clone, Deserialize)]
pub struct Posture {
    pub score: i64,
    pub quantum_risk: String,
    pub total_assets: i64,
    pub vulnerable_assets: i64,
    pub pqc_assets: i64,
    pub unknown_assets: i64,
    pub category_scores: HashMap<String, i64>,
    pub top_risks: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub last_scan_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct InventoryEntry {
    pub algorithm: String,
    pub count: i64,
    pub quantum_status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Inventory {
    pub total_assets: i64,
    pub quantum_vulnerable: i64,
    pub quantum_safe: i64,
    pub unknown: i64,
    pub by_algorithm: Vec<InventoryEntry>,
    pub scans_run: i64,
}

// ---- Client -----------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Client {
    base_url: String,
    api_key: String,
    http: reqwest::Client,
}

impl Client {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self::with_timeout(base_url, api_key, Duration::from_secs(15))
    }

    pub fn with_timeout(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        let mut base_url = base_url.into();
        if base_url.is_empty() {
            base_url = DEFAULT_BASE_URL.to_string();
        }
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            http: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .expect("building a reqwest client with only a timeout cannot fail"),
        }
    }

    async fn request<T: for<'de> Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T, Error> {
        let url = format!("{}/v1{}", self.base_url, path);
        let mut req = self.http.request(method, &url);
        if !self.api_key.is_empty() {
            req = req.header("X-API-Key", &self.api_key);
        }
        if let Some(payload) = body {
            req = req.json(&payload);
        }

        let response = req.send().await?;
        let status = response.status();
        let text = response.text().await?;

        if status.is_client_error() || status.is_server_error() {
            // The API returns {"detail": "..."}; anything else (a proxy's
            // HTML error page, say) is surfaced raw rather than swallowed,
            // because "unknown error" helps nobody debug.
            let detail = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|v| {
                    v.get("detail").map(|d| match d {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                })
                .unwrap_or_else(|| text.trim().to_string());
            return Err(Error::Api {
                status: status.as_u16(),
                detail,
            });
        }

        serde_json::from_str(&text).map_err(|e| Error::Decode(e.to_string()))
    }

    // ---- Keys ---------------------------------------------------------------

    /// Generate a keypair. `purpose` is "kem", "signature", or "hybrid_kem".
    pub async fn create_key(&self, purpose: &str, label: Option<&str>) -> Result<Key, Error> {
        let mut body = json!({ "purpose": purpose });
        if let Some(label) = label {
            body["label"] = json!(label);
        }
        self.request(reqwest::Method::POST, "/keys", Some(body))
            .await
    }

    pub async fn get_key(&self, key_id: &str) -> Result<Key, Error> {
        self.request(reqwest::Method::GET, &format!("/keys/{key_id}"), None)
            .await
    }

    // ---- Encrypt / decrypt --------------------------------------------------

    /// Seal `plaintext`.
    ///
    /// Pass `None` for `key_id` to use the one-line path, where the
    /// platform provisions and reuses a managed key for the account and
    /// reports which one it used.
    pub async fn encrypt(
        &self,
        key_id: Option<&str>,
        plaintext: &[u8],
    ) -> Result<Encrypted, Error> {
        let mut body = json!({ "plaintext": BASE64.encode(plaintext) });
        if let Some(key_id) = key_id {
            body["key_id"] = json!(key_id);
        }
        self.request(reqwest::Method::POST, "/encrypt", Some(body))
            .await
    }

    pub async fn decrypt(&self, sealed: &Encrypted) -> Result<Vec<u8>, Error> {
        #[derive(Deserialize)]
        struct Plaintext {
            plaintext: String,
        }
        let body = json!({
            "key_id": sealed.key_id,
            "ciphertext_kem": sealed.ciphertext_kem,
            "ciphertext_payload": sealed.ciphertext_payload,
            "nonce": sealed.nonce,
        });
        let out: Plaintext = self
            .request(reqwest::Method::POST, "/decrypt", Some(body))
            .await?;
        BASE64
            .decode(out.plaintext)
            .map_err(|e| Error::Decode(format!("plaintext was not valid base64: {e}")))
    }

    // ---- Sign / verify ------------------------------------------------------

    pub async fn sign(&self, key_id: &str, message: &[u8]) -> Result<Signature, Error> {
        let body = json!({ "key_id": key_id, "message": BASE64.encode(message) });
        self.request(reqwest::Method::POST, "/sign", Some(body))
            .await
    }

    /// Check a signature.
    ///
    /// `Ok(false)` means the signature did not verify; `Err` means the
    /// check could not be performed. Those are different outcomes and must
    /// not be conflated — treating an unreachable API as "invalid
    /// signature" is how a verification step silently becomes a no-op.
    pub async fn verify(
        &self,
        key_id: &str,
        message: &[u8],
        signature: &str,
    ) -> Result<bool, Error> {
        #[derive(Deserialize)]
        struct Valid {
            valid: bool,
        }
        let body = json!({
            "key_id": key_id,
            "message": BASE64.encode(message),
            "signature": signature,
        });
        let out: Valid = self
            .request(reqwest::Method::POST, "/verify", Some(body))
            .await?;
        Ok(out.valid)
    }

    // ---- AI analysis --------------------------------------------------------

    pub async fn analyze(&self, context: Value) -> Result<Analysis, Error> {
        self.request(
            reqwest::Method::POST,
            "/analyze",
            Some(json!({ "context": context })),
        )
        .await
    }

    // ---- Scanner ------------------------------------------------------------

    /// Scan submitted source or manifest text. Nothing is fetched — only
    /// what you pass is scanned.
    pub async fn scan_code(&self, filename: &str, content: &str) -> Result<ScanRun, Error> {
        let body = json!({ "filename": filename, "content": content });
        self.request(reqwest::Method::POST, "/scan/code", Some(body))
            .await
    }

    /// Probe a live TLS endpoint and record what it actually negotiates,
    /// including its certificate's key algorithm.
    pub async fn scan_tls(&self, host: &str, port: u16) -> Result<ScanRun, Error> {
        let port = if port == 0 { 443 } else { port };
        let body = json!({ "host": host, "port": port });
        self.request(reqwest::Method::POST, "/scan/tls", Some(body))
            .await
    }

    pub async fn scan_assets(&self, scan_id: &str) -> Result<Vec<CryptoAsset>, Error> {
        self.request(
            reqwest::Method::GET,
            &format!("/scans/{scan_id}/assets"),
            None,
        )
        .await
    }

    // ---- Posture / inventory ------------------------------------------------

    pub async fn security_posture(&self) -> Result<Posture, Error> {
        self.request(reqwest::Method::GET, "/security/posture", None)
            .await
    }

    pub async fn crypto_inventory(&self) -> Result<Inventory, Error> {
        self.request(reqwest::Method::GET, "/inventory", None).await
    }
}
