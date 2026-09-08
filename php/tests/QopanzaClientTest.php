<?php

declare(strict_types=1);

namespace Qopanza\Tests;

use PHPUnit\Framework\TestCase;
use Qopanza\QopanzaApiException;
use Qopanza\QopanzaClient;

/**
 * The transport is injected rather than the client mocked, so request
 * encoding and response decoding are both exercised — the two places a
 * client library actually breaks.
 */
final class QopanzaClientTest extends TestCase
{
    /** @var list<array{method:string,url:string,body:?string,headers:list<string>}> */
    private array $calls = [];

    private function clientReturning(int $status, string $body): QopanzaClient
    {
        $this->calls = [];
        $transport = function (string $method, string $url, ?string $requestBody, array $headers) use ($status, $body): array {
            $this->calls[] = [
                'method' => $method,
                'url' => $url,
                'body' => $requestBody,
                'headers' => $headers,
            ];
            return [$status, $body];
        };
        return new QopanzaClient('http://api.test', 'qsk_test', 15, $transport);
    }

    /** @return array<string,mixed> */
    private function lastRequestBody(): array
    {
        return json_decode($this->calls[0]['body'] ?? '{}', true);
    }

    public function testSendsApiKeyHeaderAndV1Prefix(): void
    {
        $client = $this->clientReturning(201, '{"id":"k1","algorithm":"ML-KEM-768"}');
        $key = $client->createKey('kem');

        self::assertSame('k1', $key['id']);
        self::assertSame('http://api.test/v1/keys', $this->calls[0]['url']);
        self::assertContains('X-API-Key: qsk_test', $this->calls[0]['headers']);
    }

    public function testBaseUrlTrailingSlashIsHandled(): void
    {
        $calls = [];
        $transport = function (string $method, string $url, ?string $body, array $headers) use (&$calls): array {
            $calls[] = $url;
            return [200, '{"total_assets":0}'];
        };
        $client = new QopanzaClient('http://api.test/', 'k', 15, $transport);
        $client->cryptoInventory();

        self::assertSame('http://api.test/v1/inventory', $calls[0]);
    }

    public function testEncryptBase64EncodesPlaintext(): void
    {
        $client = $this->clientReturning(200, '{"key_id":"k1"}');
        $client->encrypt('k1', 'hello world');

        self::assertSame(base64_encode('hello world'), $this->lastRequestBody()['plaintext']);
        self::assertSame('k1', $this->lastRequestBody()['key_id']);
    }

    public function testEncryptOmitsKeyIdForTheOneLinePath(): void
    {
        // Sending key_id: "" would request a key with an empty id, not the
        // managed default.
        $client = $this->clientReturning(200, '{"key_id":"managed","used_managed_key":true}');
        $sealed = $client->encrypt(null, 'data');

        self::assertArrayNotHasKey('key_id', $this->lastRequestBody());
        self::assertTrue($sealed['used_managed_key']);
    }

    public function testDecryptDecodesPlaintext(): void
    {
        $client = $this->clientReturning(200, json_encode(['plaintext' => base64_encode('recovered')]));
        $plaintext = $client->decrypt([
            'key_id' => 'k1',
            'ciphertext_kem' => 'AA',
            'ciphertext_payload' => 'BB',
            'nonce' => 'CC',
        ]);

        self::assertSame('recovered', $plaintext);
    }

    public function testRoundTripSurvivesBinaryData(): void
    {
        // Raw bytes, including a NUL, must survive base64 in both
        // directions — a string-only assumption breaks silently on binary.
        $binary = "\x00\x01\x02\xff\xfe binary";
        $client = $this->clientReturning(200, json_encode(['plaintext' => base64_encode($binary)]));
        self::assertSame($binary, $client->decrypt([
            'key_id' => 'k1',
            'ciphertext_kem' => 'AA',
            'ciphertext_payload' => 'BB',
            'nonce' => 'CC',
        ]));
    }

    public function testVerifyReturnsFalseForAnInvalidSignature(): void
    {
        $client = $this->clientReturning(200, '{"valid":false}');
        self::assertFalse($client->verify('k1', 'message', 'sig'));
    }

    public function testVerifyThrowsRatherThanReturningFalseWhenTheCallFails(): void
    {
        // Treating an unreachable API as "invalid signature" is how a
        // verification step silently becomes a no-op.
        $client = $this->clientReturning(500, '{"detail":"boom"}');

        $this->expectException(QopanzaApiException::class);
        $client->verify('k1', 'message', 'sig');
    }

    public function testApiExceptionCarriesStatusAndDetail(): void
    {
        $client = $this->clientReturning(409, '{"detail":"This key has been revoked and can no longer be used."}');

        try {
            $client->encrypt('k1', 'x');
            self::fail('expected QopanzaApiException');
        } catch (QopanzaApiException $e) {
            self::assertSame(409, $e->getStatusCode());
            self::assertStringContainsString('revoked', $e->getDetail());
        }
    }

    public function testNonJsonErrorBodyIsSurfacedRatherThanSwallowed(): void
    {
        // A proxy's HTML error page is not our envelope. "Unknown error"
        // would help nobody debug it.
        $client = $this->clientReturning(502, '<html>502 Bad Gateway</html>');

        try {
            $client->securityPosture();
            self::fail('expected QopanzaApiException');
        } catch (QopanzaApiException $e) {
            self::assertSame(502, $e->getStatusCode());
            self::assertSame('<html>502 Bad Gateway</html>', $e->getDetail());
        }
    }

    public function testFailedScanKeepsRiskScoreNull(): void
    {
        // A failed scan reporting 0 would read as "perfectly clean".
        $client = $this->clientReturning(201, '{"id":"s1","status":"failed","error":"no such host","risk_score":null}');
        $run = $client->scanTls('bad.invalid');

        self::assertSame('failed', $run['status']);
        self::assertNull($run['risk_score']);
        self::assertNotEmpty($run['error']);
    }

    public function testScanTlsDefaultsToPort443(): void
    {
        $client = $this->clientReturning(201, '{"id":"s1"}');
        $client->scanTls('example.com');

        self::assertSame(443, $this->lastRequestBody()['port']);
    }

    public function testPostureDecodesNestedStructures(): void
    {
        $client = $this->clientReturning(200, json_encode([
            'score' => 54,
            'quantum_risk' => 'high',
            'category_scores' => ['certificates' => 40, 'hashing' => 0],
            'top_risks' => ['RSA (3 assets)'],
            'last_scan_at' => '2026-08-18T18:49:04Z',
        ]));
        $posture = $client->securityPosture();

        self::assertSame(54, $posture['score']);
        self::assertSame(40, $posture['category_scores']['certificates']);
        self::assertCount(1, $posture['top_risks']);
    }

    public function testKeyIdIsUrlEncodedInThePath(): void
    {
        // A key id is a uuid today, but building paths by concatenation is
        // how a path-traversal bug gets in later.
        $client = $this->clientReturning(200, '{"id":"x"}');
        $client->getKey('weird/id with spaces');

        self::assertStringContainsString('weird%2Fid%20with%20spaces', $this->calls[0]['url']);
    }
}
