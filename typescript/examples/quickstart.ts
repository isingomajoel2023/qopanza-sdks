/**
 * Run against a local `docker compose up` stack:
 *   cd sdks/typescript && npm install
 *   npx ts-node examples/quickstart.ts
 *
 * Signs up for a fresh account to get a real API key first — this SDK
 * covers the crypto/analyze endpoints only, account signup isn't part of
 * it yet, so this example makes that one call directly with fetch.
 */
import { QopanzaClient } from "../src/client";

const BASE_URL = "http://localhost:8000";

async function signUpAndGetApiKey(): Promise<string> {
  const resp = await fetch(`${BASE_URL}/v1/accounts`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "quickstart-ts@example.com", password: "quickstart-password-1" }),
  });
  if (resp.status === 409) {
    throw new Error(
      "Account already exists — this quickstart signs up fresh each run. " +
        "Change the email above or delete the account first.",
    );
  }
  if (!resp.ok) {
    throw new Error(`Signup failed: ${resp.status}`);
  }
  const body = (await resp.json()) as { api_key: string };
  return body.api_key;
}

async function main() {
  const apiKey = await signUpAndGetApiKey();
  const client = new QopanzaClient({ baseUrl: BASE_URL, apiKey });

  console.log("== Key encapsulation (encrypt/decrypt) ==");
  const kemKey = await client.createKey("kem", "quickstart-kem");
  console.log("Created KEM key:", kemKey.id);

  const plaintext = Buffer.from("hello quantum-safe world", "utf-8");
  const enc = await client.encrypt(kemKey.id, plaintext);
  const decrypted = await client.decrypt(enc);
  console.log("Round-trip OK:", Buffer.from(decrypted).toString("utf-8") === plaintext.toString("utf-8"));

  console.log("\n== Signatures ==");
  const sigKey = await client.createKey("signature", "quickstart-sig");
  const message = Buffer.from("order-42-confirmed", "utf-8");
  const signed = await client.sign(sigKey.id, message);
  const valid = await client.verify(sigKey.id, message, signed.signature);
  console.log("Signature valid:", valid);

  console.log("\n== AI security analysis ==");
  const report = await client.analyze({ algorithms_in_use: ["RSA-2048"], key_reuse_count: 3 });
  console.log("Summary:", report.summary);
  for (const finding of report.findings) {
    console.log(`  [${finding.severity}] ${finding.ruleId}: ${finding.title}`);
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
