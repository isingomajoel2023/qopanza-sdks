# qopanza/sdk (PHP)

PHP client for the Qopanza API.

> **Two homes, one codebase.** Packagist reads `composer.json` from the
> *root* of the repository it is given, and here it sits one directory
> down. So this directory is mirrored to
> [qopanza-php](https://github.com/isingomajoel2023/qopanza-php) and
> published from there as `qopanza/sdk`. The code is identical; the
> mirror exists only to satisfy that layout rule.
>
> Development happens in
> [qopanza-sdks](https://github.com/isingomajoel2023/qopanza-sdks) —
> issues and pull requests go there, so the PHP client is discussed
> alongside the eight other clients of the same API rather than in a
> repository of its own.

## Install

```bash
composer require qopanza/sdk
```

Requires PHP 8.1+ with the `curl` and `json` extensions. No runtime
dependencies beyond those.

## Usage

Get an API key by signing up first — it is shown exactly once.

```php
use Qopanza\QopanzaClient;

$client = new QopanzaClient('http://localhost:8000', $apiKey);

// One-line encryption: no key management at all.
$sealed = $client->encrypt(null, 'customer sensitive information');
echo $client->decrypt($sealed);

// Full control.
$key = $client->createKey('kem', 'order-service');
$sealed = $client->encrypt($key['id'], 'hello quantum-safe world');

$sigKey = $client->createKey('signature');
$signed = $client->sign($sigKey['id'], 'order-42-confirmed');
$valid = $client->verify($sigKey['id'], 'order-42-confirmed', $signed['signature']);

// Discovery.
$run = $client->scanTls('api.example.com');
$posture = $client->securityPosture();
```

Run the quickstart (no `composer install` needed — it uses a small
autoloader):

```bash
QOPANZA_API_KEY=qsk_... QOPANZA_BASE_URL=http://localhost:8000 \
  php examples/quickstart.php
```

## Notes

- **Raw strings, not base64.** Base64 is applied internally; passing
  pre-encoded data double-encodes it.
- **`verify()` returns `false` only for a genuinely invalid signature.**
  A failed call throws `QopanzaApiException` instead — treating an
  unreachable API as "invalid signature" is how a verification step
  silently becomes a no-op.
- **A failed scan has a null `risk_score`**, not zero.
- `QopanzaApiException::getStatusCode()` is separate from the message,
  so a 409 from a revoked key can be handled differently from a 429 rate
  limit. A status of `0` means the request never reached the API.
- The constructor takes an optional transport callable, which is how the
  test suite exercises request encoding without a network.

This client holds a secret API key, so it belongs server-side — never ship
it to a browser.

## Tests

```bash
composer install
composer test
```
