# qopanza (Rust)

Async Rust client for the Qopanza API.

## Install

```toml
[dependencies]
qopanza = { path = "../sdks/rust" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Requires Rust 1.75+.

## Usage

```rust
use qopanza::Client;

let client = Client::new("http://localhost:8000", api_key);

// One-line encryption: no key management at all.
let sealed = client.encrypt(None, b"customer sensitive information").await?;
let opened = client.decrypt(&sealed).await?;

// Full control.
let key = client.create_key("kem", Some("order-service")).await?;
let sealed = client.encrypt(Some(&key.id), b"hello").await?;

let sig_key = client.create_key("signature", None).await?;
let signed = client.sign(&sig_key.id, b"order-42").await?;
let valid = client.verify(&sig_key.id, b"order-42", &signed.signature).await?;

// Discovery.
let run = client.scan_tls("api.example.com", 443).await?;
let posture = client.security_posture().await?;
```

Run the quickstart against a local server:

```bash
QOPANZA_API_KEY=qsk_... QOPANZA_BASE_URL=http://localhost:8000 \
  cargo run --example quickstart
```

## Notes

- **Bytes, not base64.** `&[u8]` / `Vec<u8>` at the API boundary; base64 is
  applied internally.
- **`verify` returns `Result<bool, Error>`.** `Ok(false)` means the
  signature did not verify; `Err` means the check could not be performed.
  Conflating them is how a verification step silently becomes a no-op.
- **A failed scan has `risk_score: None`**, not zero.
- `Error::Api { status, detail }` keeps the status code separate so a 409
  from a revoked key can be handled differently from a 429 rate limit.
- TLS via rustls, so there is no OpenSSL build dependency.

This client holds a secret API key, so it belongs server-side.

## Tests

```bash
cargo test
```
