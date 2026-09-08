# qopanza (Go)

Go client for the Qopanza API.

## Install

```bash
go get github.com/isingomajoel2023/qopanza-sdks/go/qopanza
```

Requires Go 1.21+. No dependencies outside the standard library.

## Usage

Get an API key by signing up first — it is shown exactly once:

```bash
curl -X POST http://localhost:8000/v1/accounts \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"a-real-password"}'
```

### One-line encryption

The shortest path: don't create or manage keys at all. The platform
provisions a managed key for your account on first use and reuses it.

```go
client := qopanza.New("http://localhost:8000", apiKey)

sealed, err := client.Encrypt(ctx, "", []byte("customer sensitive information"))
opened, err := client.Decrypt(ctx, sealed)
```

### Full control

```go
key, _ := client.CreateKey(ctx, "kem", "order-service")
sealed, _ := client.Encrypt(ctx, key.ID, []byte("hello quantum-safe world"))

sigKey, _ := client.CreateKey(ctx, "signature", "order-service-sig")
signed, _ := client.Sign(ctx, sigKey.ID, []byte("order-42-confirmed"))
valid, _ := client.Verify(ctx, sigKey.ID, []byte("order-42-confirmed"), signed.Signature)
```

### Discovery

```go
run, _ := client.ScanCode(ctx, "payments.py", source)
run, _ := client.ScanTLS(ctx, "api.example.com", 443)

posture, _ := client.SecurityPosture(ctx)
fmt.Println(posture.Score, posture.QuantumRisk)
```

## Notes

- **Bytes, not base64.** `[]byte` at the API boundary; base64 is applied
  internally. Making callers encode it themselves is how a plaintext ends
  up double-encoded in production.
- **`Verify` returns `(bool, error)`.** `false` means the signature did not
  verify; a non-nil error means the check could not be performed. Treating
  an unreachable API as "invalid signature" is how a verification step
  silently becomes a no-op.
- **A failed scan has a nil `RiskScore`**, not zero — a scan that could not
  run must never read as a clean result.
- `*APIError` carries the status code separately from the message, so a 409
  from a revoked key can be handled differently from a 429 rate limit.

This client holds a secret API key, so it belongs server-side.

## Tests

```bash
go test ./...
```
