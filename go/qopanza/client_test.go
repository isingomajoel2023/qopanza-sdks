package qopanza

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The HTTP layer is faked with httptest rather than mocked at the client
// boundary, so request encoding and response decoding are both exercised
// — the two places a client library actually breaks.

func newTestServer(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return New(server.URL, "qsk_test"), server
}

func TestSendsApiKeyHeader(t *testing.T) {
	var got string
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-API-Key")
		json.NewEncoder(w).Encode(Key{ID: "k1"})
	})

	if _, err := client.CreateKey(context.Background(), "kem", ""); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	if got != "qsk_test" {
		t.Errorf("X-API-Key = %q, want %q", got, "qsk_test")
	}
}

func TestPathsArePrefixedWithV1(t *testing.T) {
	var path string
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		json.NewEncoder(w).Encode(Key{ID: "k1"})
	})

	client.CreateKey(context.Background(), "kem", "")
	if path != "/v1/keys" {
		t.Errorf("path = %q, want /v1/keys", path)
	}
}

func TestEncryptBase64EncodesPlaintext(t *testing.T) {
	var body map[string]any
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(Encrypted{KeyID: "k1"})
	})

	if _, err := client.Encrypt(context.Background(), "k1", []byte("hello world")); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	want := base64.StdEncoding.EncodeToString([]byte("hello world"))
	if body["plaintext"] != want {
		t.Errorf("plaintext = %v, want %v", body["plaintext"], want)
	}
}

func TestEncryptOmitsKeyIDForTheOneLinePath(t *testing.T) {
	// Sending key_id: "" would be a request for a key with an empty id,
	// not a request for the managed default.
	var body map[string]any
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		json.NewEncoder(w).Encode(Encrypted{KeyID: "managed", UsedManagedKey: true})
	})

	out, err := client.Encrypt(context.Background(), "", []byte("data"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, present := body["key_id"]; present {
		t.Error("key_id was sent for the one-line path; it must be omitted")
	}
	if !out.UsedManagedKey {
		t.Error("UsedManagedKey not decoded")
	}
}

func TestDecryptDecodesPlaintext(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{
			"plaintext": base64.StdEncoding.EncodeToString([]byte("recovered")),
		})
	})

	got, err := client.Decrypt(context.Background(), &Encrypted{KeyID: "k1"})
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != "recovered" {
		t.Errorf("plaintext = %q, want %q", got, "recovered")
	}
}

func TestVerifyDistinguishesFalseFromError(t *testing.T) {
	// The distinction that matters: an unreachable API must not look like
	// an invalid signature, or verification silently becomes a no-op.
	invalid, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"valid": false})
	})
	ok, err := invalid.Verify(context.Background(), "k1", []byte("m"), "sig")
	if err != nil || ok {
		t.Errorf("got (%v, %v), want (false, nil)", ok, err)
	}

	broken, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"detail":"boom"}`))
	})
	ok, err = broken.Verify(context.Background(), "k1", []byte("m"), "sig")
	if err == nil {
		t.Fatal("want an error when the call fails, got nil")
	}
	if ok {
		t.Error("want false alongside the error")
	}
}

func TestAPIErrorCarriesStatusAndDetail(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte(`{"detail":"This key has been revoked and can no longer be used."}`))
	})

	_, err := client.Encrypt(context.Background(), "k1", []byte("x"))
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusConflict {
		t.Errorf("StatusCode = %d, want 409", apiErr.StatusCode)
	}
	if apiErr.Detail != "This key has been revoked and can no longer be used." {
		t.Errorf("Detail = %q", apiErr.Detail)
	}
}

func TestNonJSONErrorBodyIsSurfacedRatherThanSwallowed(t *testing.T) {
	// A proxy's HTML error page is not our envelope. Reporting "unknown
	// error" would help nobody debug it.
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte("<html>502 Bad Gateway</html>"))
	})

	_, err := client.SecurityPosture(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %v", err)
	}
	if apiErr.Detail != "<html>502 Bad Gateway</html>" {
		t.Errorf("Detail = %q, want the raw body", apiErr.Detail)
	}
}

func TestFailedScanKeepsRiskScoreNil(t *testing.T) {
	// A failed scan reporting 0 would read as "perfectly clean".
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"s1","status":"failed","error":"no such host","risk_score":null}`))
	})

	run, err := client.ScanTLS(context.Background(), "no-such-host.invalid", 443)
	if err != nil {
		t.Fatalf("ScanTLS: %v", err)
	}
	if run.RiskScore != nil {
		t.Errorf("RiskScore = %v, want nil for a failed scan", *run.RiskScore)
	}
	if run.Status != "failed" || run.Error == "" {
		t.Errorf("failed scan not reported as such: %+v", run)
	}
}

func TestScanTLSDefaultsToPort443(t *testing.T) {
	var body map[string]any
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(ScanRun{ID: "s1"})
	})

	client.ScanTLS(context.Background(), "example.com", 0)
	if body["port"] != float64(443) {
		t.Errorf("port = %v, want 443", body["port"])
	}
}

func TestPostureDecodesNestedFields(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"score":54,"quantum_risk":"high","total_assets":8,
			"vulnerable_assets":6,"pqc_assets":2,"unknown_assets":0,
			"category_scores":{"certificates":40,"hashing":0},
			"top_risks":["RSA (3 assets)"],"recommended_actions":["RSA: migrate"],
			"last_scan_at":"2026-08-18T18:49:04Z"}`))
	})

	posture, err := client.SecurityPosture(context.Background())
	if err != nil {
		t.Fatalf("SecurityPosture: %v", err)
	}
	if posture.Score != 54 || posture.QuantumRisk != "high" {
		t.Errorf("got score=%d risk=%s", posture.Score, posture.QuantumRisk)
	}
	if posture.CategoryScores["certificates"] != 40 {
		t.Errorf("category_scores not decoded: %v", posture.CategoryScores)
	}
	if len(posture.TopRisks) != 1 {
		t.Errorf("top_risks not decoded: %v", posture.TopRisks)
	}
}

func TestBaseURLTrailingSlashIsHandled(t *testing.T) {
	var path string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		json.NewEncoder(w).Encode(Key{ID: "k1"})
	}))
	defer server.Close()

	client := New(server.URL+"/", "key")
	client.CreateKey(context.Background(), "kem", "")
	if path != "/v1/keys" {
		t.Errorf("path = %q, want /v1/keys (double slash not collapsed)", path)
	}
}

func TestContextCancellationIsPropagated(t *testing.T) {
	client, _ := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Key{ID: "k1"})
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := client.CreateKey(ctx, "kem", ""); !errors.Is(err, context.Canceled) {
		t.Errorf("want context.Canceled, got %v", err)
	}
}
