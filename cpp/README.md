# qopanza (C++)

C++17 client for the Qopanza API. Depends on libcurl (HTTP
transport) and nlohmann/json (JSON) — both widely packaged, no vendored
or header-only reimplementations for those. Base64 is the one piece
implemented directly in this SDK (`include/qopanza/base64.hpp`), since
pulling in a whole library for two small functions wasn't worth it.

## Dependencies

```bash
# Debian/Ubuntu
sudo apt-get install libcurl4-openssl-dev nlohmann-json3-dev libgtest-dev

# macOS (Homebrew)
brew install curl nlohmann-json googletest
```

`libgtest-dev`/`googletest` is only needed to build the test suite
(`QOPANZA_BUILD_TESTS`, on by default).

## Build

```bash
cd sdks/cpp
cmake -B build
cmake --build build -j
```

This builds three targets: the `qopanza` static library, the
`quickstart` example, and the `qopanza_tests` test binary.
Disable either of the latter two with `-DQOPANZA_BUILD_EXAMPLES=OFF`
/ `-DQOPANZA_BUILD_TESTS=OFF`.

## Usage

This SDK covers the crypto/analyze endpoints only — get a real API key by
signing up first (account signup isn't part of the SDK yet). See
`examples/quickstart.cpp` for the raw-libcurl signup call.

```cpp
#include "qopanza/client.hpp"

qopanza::QopanzaClient client("http://localhost:8000", api_key);

// Generate a KEM keypair
auto key = client.create_key("kem", "order-service-kem");

// Encrypt / decrypt
std::vector<unsigned char> plaintext{'h', 'e', 'l', 'l', 'o'};
auto enc = client.encrypt(key.id, plaintext);
auto decrypted = client.decrypt(enc);
assert(decrypted == plaintext);

// Signatures
auto sig_key = client.create_key("signature", "order-service-sig");
std::vector<unsigned char> message{'o', 'r', 'd', 'e', 'r'};
auto signed_result = client.sign(sig_key.id, message);
bool valid = client.verify(sig_key.id, message, signed_result.signature);

// AI security analysis
nlohmann::json context{{"algorithms_in_use", {"RSA-2048"}}, {"key_reuse_count", 3}};
auto report = client.analyze(context);
for (const auto& finding : report.findings) {
    std::cout << finding.severity << " " << finding.title << "\n";
}
```

Errors from the API throw `qopanza::QopanzaApiError`, carrying
`status_code()` and `detail()`:

```cpp
try {
    client.get_key("does-not-exist");
} catch (const qopanza::QopanzaApiError& err) {
    std::cerr << err.status_code() << ": " << err.detail() << "\n";
}
```

For testing (or any scenario needing a custom transport — a proxy, a
retry policy), construct with an injected `HttpTransport` instead of
letting the client build its own libcurl-backed one:

```cpp
auto transport = std::make_shared<MyFakeTransport>();
qopanza::QopanzaClient client("http://localhost:8000", api_key, transport);
```

## Running the example and tests

```bash
./build/quickstart          # against a local `docker compose up` stack
./build/qopanza_tests   # fakes the HTTP layer, no live server required
```
