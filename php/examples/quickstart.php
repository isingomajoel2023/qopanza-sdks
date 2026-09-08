<?php

declare(strict_types=1);

/**
 * Quickstart for the PHP SDK: one-line encryption, signing, and a scan.
 *
 *   QOPANZA_API_KEY=qsk_... php examples/quickstart.php
 *
 * Uses a hand-rolled autoloader so the example runs without `composer
 * install` — the library itself has no runtime dependencies beyond the
 * curl and json extensions.
 */

spl_autoload_register(static function (string $class): void {
    if (str_starts_with($class, 'Qopanza\\')) {
        $relative = str_replace('\\', '/', substr($class, strlen('Qopanza\\')));
        require __DIR__ . '/../src/' . $relative . '.php';
    }
});

use Qopanza\QopanzaClient;

$apiKey = getenv('QOPANZA_API_KEY') ?: '';
if ($apiKey === '') {
    fwrite(STDERR, "set QOPANZA_API_KEY (sign up at POST /v1/accounts; the key is shown once)\n");
    exit(1);
}

$client = new QopanzaClient(getenv('QOPANZA_BASE_URL') ?: 'http://localhost:8000', $apiKey);

// One-line encryption: the platform provisions and reuses a managed key,
// so there is no key management to do at all.
$sealed = $client->encrypt(null, 'customer sensitive information');
$opened = $client->decrypt($sealed);
printf("round trip: %s (managed key: %s)\n", var_export($opened, true), $sealed['used_managed_key'] ? 'true' : 'false');

// Signatures with an explicit key.
$sigKey = $client->createKey('signature', 'orders');
$signed = $client->sign($sigKey['id'], 'order-42-confirmed');
$valid = $client->verify($sigKey['id'], 'order-42-confirmed', $signed['signature']);
printf("signature valid: %s (%s)\n", $valid ? 'true' : 'false', $sigKey['algorithm']);

// Discover what cryptography a file uses.
$run = $client->scanCode('payments.py', "cipher = RSA.generate(2048)\nh = hashlib.md5(x)");
printf("scan: %d asset(s), %d quantum-vulnerable\n", $run['assets_found'], $run['quantum_vulnerable']);

$posture = $client->securityPosture();
printf("posture: %d/100 (%s risk)\n", $posture['score'], $posture['quantum_risk']);
foreach ($posture['recommended_actions'] as $action) {
    printf("  - %s\n", $action);
}
