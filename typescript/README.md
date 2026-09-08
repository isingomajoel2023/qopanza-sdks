# qopanza (TypeScript / JavaScript)

TypeScript/JavaScript client for the Qopanza API. Works as plain
JavaScript too — the published package includes compiled `.js` and
`.d.ts` files, so TypeScript is optional for consumers.

Targets Node.js 18+ (uses the global `fetch`/`AbortController`, no HTTP
library dependency). Intended for server-side use — like the Python and
Java SDKs, it holds a secret API key, which doesn't belong in a browser.

## Install (local dev)

```bash
cd sdks/typescript
npm install
npm run build
```

## Usage

This SDK covers the crypto/analyze endpoints only — get a real API key by
signing up first (account signup isn't part of the SDK yet):

```ts
const signup = await fetch("http://localhost:8000/v1/accounts", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ email: "you@example.com", password: "a-real-password" }),
}).then((r) => r.json());
const apiKey = signup.api_key; // shown once — store it
```

```ts
import { QopanzaClient } from "qopanza";

const client = new QopanzaClient({ baseUrl: "http://localhost:8000", apiKey });

// Generate a KEM keypair
const key = await client.createKey("kem", "order-service-kem");

// Encrypt / decrypt
const enc = await client.encrypt(key.id, Buffer.from("hello quantum-safe world"));
const plaintext = await client.decrypt(enc);
console.log(Buffer.from(plaintext).toString("utf-8")); // "hello quantum-safe world"

// Signatures
const sigKey = await client.createKey("signature", "order-service-sig");
const message = Buffer.from("order-42-confirmed");
const signed = await client.sign(sigKey.id, message);
const valid = await client.verify(sigKey.id, message, signed.signature);

// AI security analysis
const report = await client.analyze({ algorithms_in_use: ["RSA-2048"], key_reuse_count: 3 });
for (const finding of report.findings) {
  console.log(finding.severity, finding.title);
}
```

Plain JavaScript (CommonJS) works identically after `npm run build`:

```js
const { QopanzaClient } = require("qopanza");
const client = new QopanzaClient({ baseUrl: "http://localhost:8000", apiKey });
```

Errors from the API surface as `QopanzaApiError`, carrying
`statusCode` and `detail`:

```ts
import { QopanzaApiError } from "qopanza";

try {
  await client.getKey("does-not-exist");
} catch (err) {
  if (err instanceof QopanzaApiError) {
    console.error(err.statusCode, err.detail);
  }
}
```

See `examples/quickstart.ts` for a runnable script, and `src/client.test.ts`
for the test suite (`npm test`, no live server required — the HTTP layer
is faked at the `fetch` boundary).
