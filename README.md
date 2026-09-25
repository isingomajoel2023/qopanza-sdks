# Qopanza SDKs

Official client libraries for the [Qopanza API](https://qopanza.com) —
post-quantum cryptography and cryptographic discovery.

Encrypt and sign with the NIST standards (ML-KEM-768, ML-DSA-65,
SLH-DSA-SHA2-128S) without holding the key material yourself, and scan
your own code and live sites for the cryptography that a quantum
computer will eventually break.

## Install

| Language | Install | Registry |
|---|---|---|
| Python | `pip install qopanza` | [PyPI](https://pypi.org/project/qopanza/) |
| TypeScript / JavaScript | `npm install qopanza` | [npm](https://www.npmjs.com/package/qopanza) |
| Go | `go get github.com/isingomajoel2023/qopanza-sdks/go/qopanza` | — |
| Rust | `cargo add qopanza` | [crates.io](https://crates.io/crates/qopanza) |
| Java | `com.qopanza:qopanza` | [Maven Central](https://central.sonatype.com/artifact/com.qopanza/qopanza) |
| C# / .NET | `dotnet add package Qopanza.Sdk` | [NuGet](https://www.nuget.org/packages/Qopanza.Sdk) |
| Ruby | `gem install qopanza` | [RubyGems](https://rubygems.org/gems/qopanza) |
| PHP | `composer require qopanza/sdk` | [Packagist](https://packagist.org/packages/qopanza/sdk) |
| C++ | CMake, see [`cpp/`](cpp/) | — |

Go has no registry by design: `go get` fetches straight from this
repository. C++ has no dominant one, so it builds from source.

### For AI coding agents: the MCP server

[`mcp-server/`](mcp-server/) is not a client library but a tool server for
Claude Code, Cursor, Windsurf and Claude Desktop. It lets the agent scan
an app for exposed secrets and apply the fixes itself.

```bash
claude mcp add qopanza -e QOPANZA_API_KEY=qsk_... -- npx -y qopanza-mcp
```

Published on npm as [`qopanza-mcp`](https://www.npmjs.com/package/qopanza-mcp).
Setup for the other agents is in its [README](mcp-server/README.md).

## Getting started

```bash
pip install qopanza
```

```python
from qopanza import QopanzaClient

client = QopanzaClient(api_key="qsk_...")

# Encrypt without ever handling the key
sealed = client.encrypt(b"card number, health record, anything")
assert client.decrypt(sealed) == b"card number, health record, anything"

# Find the cryptography you already have
report = client.scan_repository(".")
for finding in report.findings:
    print(finding.severity, finding.algorithm, finding.location)
```

Every SDK follows the same shape. Each directory has its own README with
the idiomatic version for that language.

**Get an API key** at [qopanza.com](https://qopanza.com) — the free tier
needs no card.

## What each SDK does and does not do

**Does:** key encapsulation and signatures against the NIST
post-quantum standards, hybrid classical+PQC modes, cryptographic
inventory, repository and live-site scanning, and the remediation plan
that goes with a finding.

**Does not:** implement the cryptography itself. These are clients. The
primitives run server-side against [liboqs](https://openquantumsafe.org),
which is the point — a client library that shipped its own
implementation of ML-KEM would be asking you to trust our C, and you
should not have to.

## Versioning

Each SDK is versioned independently. Below `1.0.0` the interface may
change between minor versions; the release notes say so when it does.

## Contributing

Issues and pull requests are welcome. The SDKs are generated against
[`docs/openapi.json`](https://qopanza.com) and hand-finished, so a
report of an endpoint that does not round-trip correctly is especially
useful.

**Security issues do not belong in a public issue.** Email
security@qopanza.com — we will confirm within one working day.

## Licence

Apache-2.0. See [LICENSE](LICENSE).

© Gsente LLC
