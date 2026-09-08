import assert from "node:assert/strict";
import { test } from "node:test";

import { QopanzaApiError, QopanzaClient } from "./client";

test("QopanzaApiError carries status code and detail", () => {
  const err = new QopanzaApiError(404, "Key not found");
  assert.equal(err.statusCode, 404);
  assert.equal(err.detail, "Key not found");
  assert.match(err.message, /404/);
  assert.match(err.message, /Key not found/);
});

test("client strips a trailing slash from baseUrl", async () => {
  const calls: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    calls.push(String(input));
    return new Response(JSON.stringify({ id: "key-1" }), { status: 200 });
  }) as typeof fetch;

  try {
    const client = new QopanzaClient({ baseUrl: "http://localhost:8000/", apiKey: "test-key" });
    await client.getKey("key-1");
    assert.equal(calls[0], "http://localhost:8000/v1/keys/key-1");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("client raises QopanzaApiError on a non-2xx response", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    new Response(JSON.stringify({ detail: "Key not found" }), { status: 404 })) as typeof fetch;

  try {
    const client = new QopanzaClient({ apiKey: "test-key" });
    await assert.rejects(() => client.getKey("missing"), (err: unknown) => {
      assert.ok(err instanceof QopanzaApiError);
      assert.equal(err.statusCode, 404);
      assert.equal(err.detail, "Key not found");
      return true;
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("encrypt/decrypt round-trips through the wire format mapping", async () => {
  const originalFetch = globalThis.fetch;

  globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(_input);
    if (url.endsWith("/encrypt")) {
      const parsedBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(
        JSON.stringify({
          key_id: parsedBody.key_id,
          ciphertext_kem: "a2Vt",
          ciphertext_payload: "cGF5bG9hZA==",
          nonce: "bm9uY2U=",
          backend: "liboqs",
        }),
        { status: 200 },
      );
    }
    if (url.endsWith("/decrypt")) {
      const body = JSON.parse(String(init?.body));
      assert.equal(body.ciphertext_kem, "a2Vt");
      return new Response(JSON.stringify({ plaintext: Buffer.from("hello").toString("base64") }), { status: 200 });
    }
    throw new Error(`unexpected request to ${url}`);
  }) as typeof fetch;

  try {
    const client = new QopanzaClient({ apiKey: "test-key" });
    const enc = await client.encrypt("key-1", Buffer.from("hello"));
    assert.equal(enc.keyId, "key-1");
    assert.equal(enc.ciphertextKem, "a2Vt");

    const plaintext = await client.decrypt(enc);
    assert.equal(Buffer.from(plaintext).toString("utf-8"), "hello");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
