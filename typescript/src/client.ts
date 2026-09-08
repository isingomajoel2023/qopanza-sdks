/**
 * TypeScript/JavaScript client for the Qopanza API.
 *
 * Covers the crypto/analyze endpoints only (keys, encrypt, decrypt, sign,
 * verify, analyze) — account signup, billing, usage, support, and
 * webhooks aren't part of this SDK yet, same scoping as the Python and
 * Java SDKs. Get a real API key by signing up first:
 *
 *   const signup = await fetch("http://localhost:8000/v1/accounts", {
 *     method: "POST",
 *     headers: { "Content-Type": "application/json" },
 *     body: JSON.stringify({ email: "you@example.com", password: "a-real-password" }),
 *   }).then((r) => r.json());
 *   const apiKey = signup.api_key; // shown once — store it
 *
 * Targets Node.js 18+ (relies on the global `fetch`/`AbortController`).
 * Not intended for browser use — it holds a secret API key, which
 * belongs server-side, same as this API's other SDKs.
 */

export class QopanzaApiError extends Error {
  readonly statusCode: number;
  readonly detail: string;

  constructor(statusCode: number, detail: string) {
    super(`[${statusCode}] ${detail}`);
    this.name = "QopanzaApiError";
    this.statusCode = statusCode;
    this.detail = detail;
  }
}

export type KeyPurpose = "kem" | "signature";

export interface KeyResponse {
  id: string;
  purpose: KeyPurpose;
  algorithm: string;
  backend: string;
  publicKey: string; // base64
  createdAt: string;
  label: string | null;
  expiresAt: string | null;
}

export interface EncryptResult {
  keyId: string;
  ciphertextKem: string; // base64
  ciphertextPayload: string; // base64
  nonce: string; // base64
  backend: string;
}

export interface SignResult {
  keyId: string;
  signature: string; // base64
  backend: string;
}

export interface AnalysisFinding {
  severity: "info" | "low" | "medium" | "high" | "critical";
  ruleId: string;
  title: string;
  detail: string;
  recommendation: string;
}

export interface AnalyzeResult {
  findings: AnalysisFinding[];
  summary: string;
  generatedBy: string; // "rules" | "rules+ai"
}

export interface QopanzaClientOptions {
  baseUrl?: string;
  apiKey?: string;
  timeoutMs?: number;
}

function b64encode(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

function b64decode(data: string): Uint8Array {
  return new Uint8Array(Buffer.from(data, "base64"));
}

/** Wire-format (snake_case) shapes returned by the API, before we map
 * them into the camelCase types this SDK exposes. */
interface KeyResponseWire {
  id: string;
  purpose: KeyPurpose;
  algorithm: string;
  backend: string;
  public_key: string;
  created_at: string;
  label: string | null;
  expires_at: string | null;
}

interface EncryptResponseWire {
  key_id: string;
  ciphertext_kem: string;
  ciphertext_payload: string;
  nonce: string;
  backend: string;
}

interface SignResponseWire {
  key_id: string;
  signature: string;
  backend: string;
}

interface AnalyzeResponseWire {
  findings: { severity: string; rule_id: string; title: string; detail: string; recommendation: string }[];
  summary: string;
  generated_by: string;
}

export class QopanzaClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly timeoutMs: number;

  constructor(options: QopanzaClientOptions = {}) {
    this.baseUrl = `${(options.baseUrl ?? "http://localhost:8000").replace(/\/$/, "")}/v1`;
    this.apiKey = options.apiKey;
    this.timeoutMs = options.timeoutMs ?? 15_000;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let resp: Response;
    try {
      resp = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          "Content-Type": "application/json",
          ...(this.apiKey ? { "X-API-Key": this.apiKey } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    const text = await resp.text();
    const data = text.length > 0 ? JSON.parse(text) : undefined;

    if (!resp.ok) {
      const detail =
        data && typeof data === "object" && "detail" in data ? String((data as { detail: unknown }).detail) : text;
      throw new QopanzaApiError(resp.status, detail);
    }
    return data as T;
  }

  // -- Keys -------------------------------------------------------------

  async createKey(purpose: KeyPurpose, label?: string): Promise<KeyResponse> {
    const resp = await this.request<KeyResponseWire>("POST", "/keys", { purpose, label: label ?? null });
    return fromKeyWire(resp);
  }

  async getKey(keyId: string): Promise<KeyResponse> {
    const resp = await this.request<KeyResponseWire>("GET", `/keys/${keyId}`);
    return fromKeyWire(resp);
  }

  // -- Encrypt / Decrypt -------------------------------------------------

  async encrypt(keyId: string, plaintext: Uint8Array): Promise<EncryptResult> {
    const resp = await this.request<EncryptResponseWire>("POST", "/encrypt", {
      key_id: keyId,
      plaintext: b64encode(plaintext),
    });
    return {
      keyId: resp.key_id,
      ciphertextKem: resp.ciphertext_kem,
      ciphertextPayload: resp.ciphertext_payload,
      nonce: resp.nonce,
      backend: resp.backend,
    };
  }

  async decrypt(enc: EncryptResult): Promise<Uint8Array> {
    const resp = await this.request<{ plaintext: string }>("POST", "/decrypt", {
      key_id: enc.keyId,
      ciphertext_kem: enc.ciphertextKem,
      ciphertext_payload: enc.ciphertextPayload,
      nonce: enc.nonce,
    });
    return b64decode(resp.plaintext);
  }

  // -- Sign / Verify ------------------------------------------------------

  async sign(keyId: string, message: Uint8Array): Promise<SignResult> {
    const resp = await this.request<SignResponseWire>("POST", "/sign", {
      key_id: keyId,
      message: b64encode(message),
    });
    return { keyId: resp.key_id, signature: resp.signature, backend: resp.backend };
  }

  async verify(keyId: string, message: Uint8Array, signature: string): Promise<boolean> {
    const resp = await this.request<{ valid: boolean }>("POST", "/verify", {
      key_id: keyId,
      message: b64encode(message),
      signature,
    });
    return resp.valid;
  }

  // -- AI analysis ----------------------------------------------------------

  async analyze(context: Record<string, unknown>): Promise<AnalyzeResult> {
    const resp = await this.request<AnalyzeResponseWire>("POST", "/analyze", { context });
    return {
      findings: resp.findings.map((f) => ({
        severity: f.severity as AnalysisFinding["severity"],
        ruleId: f.rule_id,
        title: f.title,
        detail: f.detail,
        recommendation: f.recommendation,
      })),
      summary: resp.summary,
      generatedBy: resp.generated_by,
    };
  }
}

function fromKeyWire(resp: KeyResponseWire): KeyResponse {
  return {
    id: resp.id,
    purpose: resp.purpose,
    algorithm: resp.algorithm,
    backend: resp.backend,
    publicKey: resp.public_key,
    createdAt: resp.created_at,
    label: resp.label,
    expiresAt: resp.expires_at,
  };
}
