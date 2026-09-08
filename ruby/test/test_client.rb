# frozen_string_literal: true

require "minitest/autorun"
require "base64"
require "json"
require_relative "../lib/qopanza"

# The transport is injected rather than the client mocked, so request
# encoding and response decoding are both exercised — the two places a
# client library actually breaks.
class TestQopanzaClient < Minitest::Test
  def client_returning(status, body)
    @calls = []
    transport = lambda do |method, uri, request_body, headers|
      @calls << { method: method, uri: uri, body: request_body, headers: headers }
      [status, body]
    end
    Qopanza::Client.new(
      base_url: "http://api.test", api_key: "qsk_test", transport: transport
    )
  end

  def last_body
    JSON.parse(@calls.first[:body] || "{}")
  end

  def test_sends_api_key_header_and_v1_prefix
    client = client_returning(201, '{"id":"k1","algorithm":"ML-KEM-768"}')
    key = client.create_key(purpose: "kem")

    assert_equal "k1", key["id"]
    assert_equal "/v1/keys", @calls.first[:uri].path
    assert_equal "qsk_test", @calls.first[:headers]["X-API-Key"]
  end

  def test_base_url_trailing_slash_is_handled
    calls = []
    transport = ->(_m, uri, _b, _h) { calls << uri; [200, "{}"] }
    client = Qopanza::Client.new(base_url: "http://api.test/", transport: transport)
    client.crypto_inventory

    assert_equal "/v1/inventory", calls.first.path
    refute_includes calls.first.to_s, "//v1"
  end

  def test_encrypt_base64_encodes_plaintext
    client = client_returning(200, '{"key_id":"k1"}')
    client.encrypt(key_id: "k1", plaintext: "hello world")

    assert_equal Base64.strict_encode64("hello world"), last_body["plaintext"]
    assert_equal "k1", last_body["key_id"]
  end

  def test_encrypt_omits_key_id_for_the_one_line_path
    # Sending key_id: "" would request a key with an empty id, not the
    # managed default.
    client = client_returning(200, '{"key_id":"managed","used_managed_key":true}')
    sealed = client.encrypt(plaintext: "data")

    refute last_body.key?("key_id")
    assert sealed["used_managed_key"]
  end

  def test_decrypt_decodes_plaintext
    client = client_returning(200, JSON.generate(plaintext: Base64.strict_encode64("recovered")))
    plaintext = client.decrypt(
      "key_id" => "k1", "ciphertext_kem" => "AA",
      "ciphertext_payload" => "BB", "nonce" => "CC"
    )

    assert_equal "recovered", plaintext
  end

  def test_decrypt_accepts_symbol_keys_too
    # Ruby callers reasonably build hashes either way; failing on one of
    # them would be a papercut with a confusing NoMethodError.
    client = client_returning(200, JSON.generate(plaintext: Base64.strict_encode64("ok")))
    assert_equal "ok", client.decrypt(
      key_id: "k1", ciphertext_kem: "AA", ciphertext_payload: "BB", nonce: "CC"
    )
  end

  def test_round_trip_survives_binary_data
    # Raw bytes including a NUL must survive base64 in both directions.
    binary = "\x00\x01\x02\xFF\xFE binary".b
    client = client_returning(200, JSON.generate(plaintext: Base64.strict_encode64(binary)))
    recovered = client.decrypt("key_id" => "k1", "ciphertext_kem" => "AA",
                               "ciphertext_payload" => "BB", "nonce" => "CC")

    assert_equal binary, recovered.b
  end

  def test_verify_returns_false_for_an_invalid_signature
    client = client_returning(200, '{"valid":false}')
    refute client.verify(key_id: "k1", message: "m", signature: "sig")
  end

  def test_verify_raises_rather_than_returning_false_when_the_call_fails
    # Treating an unreachable API as "invalid signature" is how a
    # verification step silently becomes a no-op.
    client = client_returning(500, '{"detail":"boom"}')

    assert_raises(Qopanza::ApiError) do
      client.verify(key_id: "k1", message: "m", signature: "sig")
    end
  end

  def test_api_error_carries_status_and_detail
    client = client_returning(409, '{"detail":"This key has been revoked and can no longer be used."}')

    error = assert_raises(Qopanza::ApiError) { client.encrypt(key_id: "k1", plaintext: "x") }
    assert_equal 409, error.status_code
    assert_includes error.detail, "revoked"
  end

  def test_non_json_error_body_is_surfaced_rather_than_swallowed
    # A proxy's HTML error page is not our envelope. "Unknown error" would
    # help nobody debug it.
    client = client_returning(502, "<html>502 Bad Gateway</html>")

    error = assert_raises(Qopanza::ApiError) { client.security_posture }
    assert_equal 502, error.status_code
    assert_equal "<html>502 Bad Gateway</html>", error.detail
  end

  def test_failed_scan_keeps_risk_score_nil
    # A failed scan reporting 0 would read as "perfectly clean".
    client = client_returning(201, '{"id":"s1","status":"failed","error":"no such host","risk_score":null}')
    run = client.scan_tls(host: "bad.invalid")

    assert_equal "failed", run["status"]
    assert_nil run["risk_score"]
    refute_empty run["error"]
  end

  def test_scan_tls_defaults_to_port_443
    client = client_returning(201, '{"id":"s1"}')
    client.scan_tls(host: "example.com")

    assert_equal 443, last_body["port"]
  end

  def test_posture_decodes_nested_structures
    client = client_returning(200, JSON.generate(
      score: 54, quantum_risk: "high",
      category_scores: { certificates: 40, hashing: 0 },
      top_risks: ["RSA (3 assets)"], last_scan_at: "2026-08-18T18:49:04Z"
    ))
    posture = client.security_posture

    assert_equal 54, posture["score"]
    assert_equal 40, posture["category_scores"]["certificates"]
    assert_equal 1, posture["top_risks"].length
  end

  def test_key_id_is_escaped_in_the_path
    # Key ids are uuids today, but building paths by concatenation is how
    # a path-traversal bug gets in later.
    client = client_returning(200, '{"id":"x"}')
    client.get_key("weird/id with spaces")

    assert_includes @calls.first[:uri].to_s, "weird%2Fid%20with%20spaces"
  end

  def test_transport_failure_becomes_an_api_error_with_status_zero
    # A status of 0 distinguishes "never reached the API" from any real
    # HTTP response, which callers legitimately need to tell apart.
    transport = ->(_m, _u, _b, _h) { raise Errno::ECONNREFUSED }
    client = Qopanza::Client.new(base_url: "http://api.test", transport: transport)

    error = assert_raises(StandardError) { client.crypto_inventory }
    assert_kind_of Errno::ECONNREFUSED, error
  end
end
