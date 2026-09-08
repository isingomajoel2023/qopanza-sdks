//! The HTTP layer is faked with a real local server (wiremock) rather than
//! mocked at the client boundary, so request encoding and response
//! decoding are both exercised — the two places a client library actually
//! breaks.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use qopanza::{Client, Encrypted, Error};
use serde_json::json;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn server_with(mock: Mock) -> (MockServer, Client) {
    let server = MockServer::start().await;
    server.register(mock).await;
    let client = Client::new(server.uri(), "qsk_test");
    (server, client)
}

#[tokio::test]
async fn sends_api_key_header_and_v1_prefix() {
    let (_server, client) = server_with(
        Mock::given(method("POST"))
            .and(path("/v1/keys"))
            .and(header("X-API-Key", "qsk_test"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "k1", "purpose": "kem", "algorithm": "ML-KEM-768",
                "backend": "liboqs", "public_key": "AAAA", "created_at": "2026-01-01T00:00:00Z",
                "label": null, "expires_at": null
            }))),
    )
    .await;

    let key = client.create_key("kem", None).await.expect("create_key");
    assert_eq!(key.id, "k1");
    assert_eq!(key.algorithm, "ML-KEM-768");
    // Absent in the response, so the documented default must apply.
    assert_eq!(key.version, 1);
    assert!(!key.client_managed);
}

#[tokio::test]
async fn encrypt_base64_encodes_plaintext() {
    let expected = BASE64.encode(b"hello world");
    let (_server, client) = server_with(
        Mock::given(method("POST"))
            .and(path("/v1/encrypt"))
            .and(body_json(json!({ "key_id": "k1", "plaintext": expected })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "key_id": "k1", "ciphertext_kem": "AA", "ciphertext_payload": "BB",
                "nonce": "CC", "backend": "liboqs", "used_managed_key": false
            }))),
    )
    .await;

    let sealed = client
        .encrypt(Some("k1"), b"hello world")
        .await
        .expect("encrypt");
    assert_eq!(sealed.key_id, "k1");
}

#[tokio::test]
async fn encrypt_omits_key_id_for_the_one_line_path() {
    // Sending key_id: "" would request a key with an empty id, not the
    // managed default.
    let (_server, client) = server_with(
        Mock::given(method("POST"))
            .and(path("/v1/encrypt"))
            .and(body_json(json!({ "plaintext": BASE64.encode(b"data") })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "key_id": "managed", "ciphertext_kem": "AA", "ciphertext_payload": "BB",
                "nonce": "CC", "backend": "liboqs", "used_managed_key": true
            }))),
    )
    .await;

    let sealed = client.encrypt(None, b"data").await.expect("encrypt");
    assert!(sealed.used_managed_key);
    assert_eq!(sealed.key_id, "managed");
}

#[tokio::test]
async fn decrypt_decodes_plaintext() {
    let (_server, client) = server_with(
        Mock::given(method("POST"))
            .and(path("/v1/decrypt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "plaintext": BASE64.encode(b"recovered")
            }))),
    )
    .await;

    let sealed = Encrypted {
        key_id: "k1".into(),
        ciphertext_kem: "AA".into(),
        ciphertext_payload: "BB".into(),
        nonce: "CC".into(),
        backend: String::new(),
        used_managed_key: false,
    };
    assert_eq!(
        client.decrypt(&sealed).await.expect("decrypt"),
        b"recovered"
    );
}

#[tokio::test]
async fn verify_distinguishes_false_from_error() {
    // The distinction that matters: an unreachable API must not look like
    // an invalid signature, or verification silently becomes a no-op.
    let (_invalid, client) = server_with(
        Mock::given(method("POST"))
            .and(path("/v1/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "valid": false }))),
    )
    .await;
    assert!(!client.verify("k1", b"m", "sig").await.unwrap());

    let (_broken, client) = server_with(
        Mock::given(method("POST"))
            .and(path("/v1/verify"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({ "detail": "boom" }))),
    )
    .await;
    assert!(client.verify("k1", b"m", "sig").await.is_err());
}

#[tokio::test]
async fn api_error_carries_status_and_detail() {
    let (_server, client) = server_with(
        Mock::given(method("POST"))
            .and(path("/v1/encrypt"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "detail": "This key has been revoked and can no longer be used."
            }))),
    )
    .await;

    match client.encrypt(Some("k1"), b"x").await {
        Err(Error::Api { status, detail }) => {
            assert_eq!(status, 409);
            assert!(detail.contains("revoked"), "detail was {detail:?}");
        }
        other => panic!("want Error::Api, got {other:?}"),
    }
}

#[tokio::test]
async fn non_json_error_body_is_surfaced_rather_than_swallowed() {
    // A proxy's HTML error page is not our envelope. "Unknown error" would
    // help nobody debug it.
    let (_server, client) = server_with(
        Mock::given(method("GET"))
            .and(path("/v1/security/posture"))
            .respond_with(
                ResponseTemplate::new(502).set_body_string("<html>502 Bad Gateway</html>"),
            ),
    )
    .await;

    match client.security_posture().await {
        Err(Error::Api { status, detail }) => {
            assert_eq!(status, 502);
            assert_eq!(detail, "<html>502 Bad Gateway</html>");
        }
        other => panic!("want Error::Api, got {other:?}"),
    }
}

#[tokio::test]
async fn failed_scan_keeps_risk_score_none() {
    // A failed scan reporting 0 would read as "perfectly clean".
    let (_server, client) = server_with(
        Mock::given(method("POST"))
            .and(path("/v1/scan/tls"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "s1", "source_type": "tls", "target": "bad.invalid:443",
                "status": "failed", "error": "no such host",
                "assets_found": 0, "quantum_vulnerable": 0, "quantum_safe": 0,
                "risk_score": null, "created_at": "2026-01-01T00:00:00Z", "completed_at": null
            }))),
    )
    .await;

    let run = client.scan_tls("bad.invalid", 443).await.expect("scan_tls");
    assert_eq!(run.status, "failed");
    assert!(run.risk_score.is_none());
    assert!(run.error.is_some());
}

#[tokio::test]
async fn scan_tls_defaults_to_port_443() {
    let (_server, client) = server_with(
        Mock::given(method("POST"))
            .and(path("/v1/scan/tls"))
            .and(body_json(json!({ "host": "example.com", "port": 443 })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "s1", "source_type": "tls", "target": "example.com:443",
                "status": "completed", "error": null,
                "assets_found": 2, "quantum_vulnerable": 1, "quantum_safe": 1,
                "risk_score": 70, "created_at": "2026-01-01T00:00:00Z",
                "completed_at": "2026-01-01T00:00:01Z"
            }))),
    )
    .await;

    let run = client.scan_tls("example.com", 0).await.expect("scan_tls");
    assert_eq!(run.risk_score, Some(70));
}

#[tokio::test]
async fn posture_decodes_nested_fields() {
    let (_server, client) = server_with(
        Mock::given(method("GET"))
            .and(path("/v1/security/posture"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "score": 54, "quantum_risk": "high", "total_assets": 8,
                "vulnerable_assets": 6, "pqc_assets": 2, "unknown_assets": 0,
                "category_scores": { "certificates": 40, "hashing": 0 },
                "top_risks": ["RSA (3 assets)"],
                "recommended_actions": ["RSA: migrate to ML-KEM-768"],
                "last_scan_at": "2026-08-18T18:49:04Z"
            }))),
    )
    .await;

    let posture = client.security_posture().await.expect("posture");
    assert_eq!(posture.score, 54);
    assert_eq!(posture.category_scores["certificates"], 40);
    assert_eq!(posture.top_risks.len(), 1);
    assert!(posture.last_scan_at.is_some());
}

#[tokio::test]
async fn base_url_trailing_slash_is_handled() {
    let server = MockServer::start().await;
    server
        .register(
            Mock::given(method("GET"))
                .and(path("/v1/inventory"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "total_assets": 0, "quantum_vulnerable": 0, "quantum_safe": 0,
                    "unknown": 0, "by_algorithm": [], "scans_run": 0
                }))),
        )
        .await;

    let client = Client::new(format!("{}/", server.uri()), "k");
    assert_eq!(
        client
            .crypto_inventory()
            .await
            .expect("inventory")
            .total_assets,
        0
    );
}
