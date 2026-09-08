<?php

declare(strict_types=1);

namespace Qopanza;

/**
 * PHP client for the Qopanza API.
 *
 * Covers the crypto endpoints (keys, encrypt, decrypt, sign, verify), the
 * AI analysis endpoint, and the scanner/posture endpoints that make the
 * API useful from CI. Account signup, billing and support are dashboard
 * concerns and are not part of this SDK — the same scoping the Python,
 * Go, Rust, TypeScript and Java SDKs use.
 *
 * Byte handling is raw strings at the API boundary with base64 applied
 * internally: base64 is a wire-format detail, and making callers encode it
 * themselves is how a plaintext ends up double-encoded in production.
 *
 * This client holds a secret API key, so it belongs server-side — never
 * ship it to a browser.
 *
 *   $client = new QopanzaClient('http://localhost:8000', $apiKey);
 *   $sealed = $client->encrypt(null, 'customer sensitive information');
 *   echo $client->decrypt($sealed);
 */
final class QopanzaClient
{
    public const DEFAULT_BASE_URL = 'http://localhost:8000';

    private string $baseUrl;
    private string $apiKey;
    private int $timeoutSeconds;

    /** @var callable|null Injected transport, for tests. */
    private $transport;

    /**
     * @param callable|null $transport Optional transport override with the
     *   signature fn(string $method, string $url, ?string $body, array $headers): array{0:int,1:string}
     *   returning [statusCode, responseBody]. Exists so the test suite can
     *   exercise request encoding and response decoding without a network,
     *   which is where a client library actually breaks.
     */
    public function __construct(
        string $baseUrl = self::DEFAULT_BASE_URL,
        string $apiKey = '',
        int $timeoutSeconds = 15,
        ?callable $transport = null
    ) {
        $this->baseUrl = rtrim($baseUrl === '' ? self::DEFAULT_BASE_URL : $baseUrl, '/');
        $this->apiKey = $apiKey;
        $this->timeoutSeconds = $timeoutSeconds;
        $this->transport = $transport;
    }

    /**
     * @param array<string,mixed>|null $body
     * @return array<string,mixed>|list<mixed>
     * @throws QopanzaApiException
     */
    private function request(string $method, string $path, ?array $body = null)
    {
        $url = $this->baseUrl . '/v1' . $path;
        $encoded = $body === null ? null : json_encode($body, JSON_THROW_ON_ERROR);

        $headers = ['Content-Type: application/json'];
        if ($this->apiKey !== '') {
            $headers[] = 'X-API-Key: ' . $this->apiKey;
        }

        [$status, $responseBody] = $this->transport !== null
            ? ($this->transport)($method, $url, $encoded, $headers)
            : $this->send($method, $url, $encoded, $headers);

        if ($status >= 400) {
            throw new QopanzaApiException($status, self::extractDetail($responseBody));
        }

        if ($responseBody === '') {
            return [];
        }

        $decoded = json_decode($responseBody, true);
        if (!is_array($decoded)) {
            throw new QopanzaApiException($status, 'Response was not valid JSON: ' . $responseBody);
        }
        return $decoded;
    }

    /**
     * The API returns {"detail": "..."} for its own errors. Anything else —
     * a proxy's HTML error page, say — is surfaced raw rather than
     * swallowed, because "unknown error" helps nobody debug.
     */
    private static function extractDetail(string $responseBody): string
    {
        $decoded = json_decode($responseBody, true);
        if (is_array($decoded) && array_key_exists('detail', $decoded)) {
            $detail = $decoded['detail'];
            return is_string($detail) ? $detail : json_encode($detail);
        }
        return trim($responseBody);
    }

    /**
     * @param list<string> $headers
     * @return array{0:int,1:string}
     */
    private function send(string $method, string $url, ?string $body, array $headers): array
    {
        $handle = curl_init($url);
        curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
        ]);
        if ($body !== null) {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
        }

        $response = curl_exec($handle);
        if ($response === false) {
            $error = curl_error($handle);
            curl_close($handle);
            throw new QopanzaApiException(0, 'Transport error: ' . $error);
        }
        $status = (int) curl_getinfo($handle, CURLINFO_HTTP_CODE);
        curl_close($handle);

        return [$status, (string) $response];
    }

    // ---- Keys ---------------------------------------------------------------

    /**
     * Generate a keypair. $purpose is "kem", "signature", or "hybrid_kem".
     *
     * @return array<string,mixed>
     */
    public function createKey(string $purpose, ?string $label = null): array
    {
        $body = ['purpose' => $purpose];
        if ($label !== null) {
            $body['label'] = $label;
        }
        return $this->request('POST', '/keys', $body);
    }

    /** @return array<string,mixed> */
    public function getKey(string $keyId): array
    {
        return $this->request('GET', '/keys/' . rawurlencode($keyId));
    }

    // ---- Encrypt / decrypt --------------------------------------------------

    /**
     * Seal $plaintext.
     *
     * Pass null for $keyId to use the one-line path, where the platform
     * provisions and reuses a managed key for the account and reports
     * which one it used in `used_managed_key`.
     *
     * @return array<string,mixed> Pass this straight back to decrypt().
     */
    public function encrypt(?string $keyId, string $plaintext): array
    {
        $body = ['plaintext' => base64_encode($plaintext)];
        if ($keyId !== null) {
            $body['key_id'] = $keyId;
        }
        return $this->request('POST', '/encrypt', $body);
    }

    /** @param array<string,mixed> $sealed */
    public function decrypt(array $sealed): string
    {
        $result = $this->request('POST', '/decrypt', [
            'key_id' => $sealed['key_id'],
            'ciphertext_kem' => $sealed['ciphertext_kem'],
            'ciphertext_payload' => $sealed['ciphertext_payload'],
            'nonce' => $sealed['nonce'],
        ]);
        return base64_decode($result['plaintext'], true) ?: '';
    }

    // ---- Sign / verify ------------------------------------------------------

    /** @return array<string,mixed> */
    public function sign(string $keyId, string $message): array
    {
        return $this->request('POST', '/sign', [
            'key_id' => $keyId,
            'message' => base64_encode($message),
        ]);
    }

    /**
     * Check a signature.
     *
     * Returns false only when the signature genuinely did not verify. A
     * failed call throws instead — treating an unreachable API as "invalid
     * signature" is how a verification step silently becomes a no-op.
     */
    public function verify(string $keyId, string $message, string $signature): bool
    {
        $result = $this->request('POST', '/verify', [
            'key_id' => $keyId,
            'message' => base64_encode($message),
            'signature' => $signature,
        ]);
        return (bool) $result['valid'];
    }

    // ---- AI analysis --------------------------------------------------------

    /**
     * @param array<string,mixed> $context
     * @return array<string,mixed>
     */
    public function analyze(array $context): array
    {
        return $this->request('POST', '/analyze', ['context' => $context]);
    }

    // ---- Scanner ------------------------------------------------------------

    /**
     * Scan submitted source or manifest text. Nothing is fetched — only
     * what you pass is scanned.
     *
     * The returned run has a null `risk_score` when it failed, rather than
     * zero: a scan that could not run must never read as a clean result.
     *
     * @return array<string,mixed>
     */
    public function scanCode(string $filename, string $content): array
    {
        return $this->request('POST', '/scan/code', [
            'filename' => $filename,
            'content' => $content,
        ]);
    }

    /**
     * Probe a live TLS endpoint and record what it actually negotiates,
     * including its certificate's key algorithm.
     *
     * @return array<string,mixed>
     */
    public function scanTls(string $host, int $port = 443): array
    {
        return $this->request('POST', '/scan/tls', [
            'host' => $host,
            'port' => $port === 0 ? 443 : $port,
        ]);
    }

    /** @return list<array<string,mixed>> */
    public function scanAssets(string $scanId): array
    {
        return $this->request('GET', '/scans/' . rawurlencode($scanId) . '/assets');
    }

    // ---- Posture / inventory ------------------------------------------------

    /**
     * The account's quantum risk score and what drives it.
     *
     * `score` runs 0-100 where higher is better, so it moves opposite to
     * `quantum_risk`. A score of 100 with a null `last_scan_at` means "no
     * vulnerable cryptography found" on an empty inventory — an absence of
     * evidence, not evidence of safety.
     *
     * @return array<string,mixed>
     */
    public function securityPosture(): array
    {
        return $this->request('GET', '/security/posture');
    }

    /** @return array<string,mixed> */
    public function cryptoInventory(): array
    {
        return $this->request('GET', '/inventory');
    }
}
