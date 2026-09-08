# qopanza (Ruby)

Ruby client for the Qopanza API.

## Install

```ruby
gem "qopanza"
```

Requires Ruby 3.0+. **No runtime dependencies** — `net/http`, `json` and
`base64` are all standard library. A security gem that drags in a tree of
transitive dependencies is a harder sell to exactly the teams most likely
to care about supply chain.

## Usage

Get an API key by signing up first — it is shown exactly once.

```ruby
require "qopanza"

client = Qopanza::Client.new(base_url: "http://localhost:8000", api_key: api_key)

# One-line encryption: no key management at all.
sealed = client.encrypt(plaintext: "customer sensitive information")
client.decrypt(sealed) # => "customer sensitive information"

# Full control.
key = client.create_key(purpose: "kem", label: "order-service")
sealed = client.encrypt(key_id: key["id"], plaintext: "hello quantum-safe world")

sig_key = client.create_key(purpose: "signature")
signed = client.sign(key_id: sig_key["id"], message: "order-42-confirmed")
client.verify(key_id: sig_key["id"], message: "order-42-confirmed", signature: signed["signature"])

# Discovery.
run = client.scan_tls(host: "api.example.com")
posture = client.security_posture
```

Run the quickstart:

```bash
QOPANZA_API_KEY=qsk_... QOPANZA_BASE_URL=http://localhost:8000 \
  ruby examples/quickstart.rb
```

## Notes

- **Raw strings, not base64.** Base64 is applied internally.
- **`verify` returns `false` only for a genuinely invalid signature.** A
  failed call raises `Qopanza::ApiError` instead — treating an
  unreachable API as "invalid signature" is how a verification step
  silently becomes a no-op.
- **A failed scan has a nil `risk_score`**, not zero.
- `ApiError#status_code` is separate from the message, so a 409 from a
  revoked key can be handled differently from a 429 rate limit. A status
  of `0` means the request never reached the API.
- `decrypt` accepts either string or symbol keys, since Ruby callers
  reasonably build hashes both ways.

This client holds a secret API key, so it belongs server-side.

## Tests

```bash
rake test
# or, without rake:
ruby -Ilib -Itest test/test_client.rb
```
