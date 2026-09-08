//! Quickstart for the Rust SDK: one-line encryption, signing, and a scan.
//!
//! ```text
//! QOPANZA_API_KEY=qsk_... cargo run --example quickstart
//! ```

use qopanza::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("QOPANZA_API_KEY")
        .expect("set QOPANZA_API_KEY (sign up at POST /v1/accounts; the key is shown once)");
    let base_url = std::env::var("QOPANZA_BASE_URL").unwrap_or_default();

    let client = Client::new(base_url, api_key);

    // One-line encryption: the platform provisions and reuses a managed
    // key, so there is no key management to do at all.
    let sealed = client
        .encrypt(None, b"customer sensitive information")
        .await?;
    let opened = client.decrypt(&sealed).await?;
    println!(
        "round trip: {:?} (managed key: {})",
        String::from_utf8_lossy(&opened),
        sealed.used_managed_key
    );

    // Signatures with an explicit key.
    let sig_key = client.create_key("signature", Some("orders")).await?;
    let signed = client.sign(&sig_key.id, b"order-42-confirmed").await?;
    let valid = client
        .verify(&sig_key.id, b"order-42-confirmed", &signed.signature)
        .await?;
    println!("signature valid: {valid} ({})", sig_key.algorithm);

    // Discover what cryptography a file uses.
    let run = client
        .scan_code(
            "payments.py",
            "cipher = RSA.generate(2048)\nh = hashlib.md5(x)",
        )
        .await?;
    println!(
        "scan: {} asset(s), {} quantum-vulnerable",
        run.assets_found, run.quantum_vulnerable
    );

    let posture = client.security_posture().await?;
    println!(
        "posture: {}/100 ({} risk)",
        posture.score, posture.quantum_risk
    );
    for action in &posture.recommended_actions {
        println!("  - {action}");
    }

    Ok(())
}
