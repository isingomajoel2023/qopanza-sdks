# Releasing the SDKs

Development happens in `sdks/` in the application repository, where CI
tests all nine against the API they are clients of. Publishing happens
from **qopanza-sdks**, because every manifest declares that repository as
its source and NuGet SourceLink embeds the URL with a commit SHA — built
anywhere else, "verify this package against its source" resolves to a
commit that does not exist.

A push to `main` that touches `sdks/` mirrors it automatically. Then you
tag in **qopanza-sdks**, not here.

## The tags

Each language releases independently. One tag, one registry.

| SDK | Tag | Registry | Version lives in |
|---|---|---|---|
| Python | `python-v0.1.0` | PyPI | `python/qopanza/__init__.py` |
| TypeScript | `npm-v0.1.0` | npm | `typescript/package.json` |
| Rust | `rust-v0.1.0` | crates.io | `rust/Cargo.toml` |
| Ruby | `ruby-v0.1.0` | RubyGems | `ruby/lib/qopanza.rb` |
| C# | `nuget-v0.1.0` | NuGet | `csharp/Qopanza.Sdk/Qopanza.Sdk.csproj` |
| Java | `java-v0.1.0` | Maven Central | `java/pom.xml` |
| MCP server | `mcp-v0.1.0` | npm (`qopanza-mcp`) | `mcp-server/package.json` |
| Go | `go/v0.1.0` | none — the tag *is* the release | the tag only |
| PHP | `v0.1.0` in **qopanza-php** | Packagist | the tag only |
| C++ | — | none | — |

**Every workflow refuses a tag that disagrees with the version in the
file.** That check is not bureaucracy: publishing 0.1.0 under a `v0.2.0`
tag produces a release nobody can ever correlate with its source, and no
registry here lets a version be reused after deletion.

`go/v0.1.0` is not a style choice — Go requires `<subdir>/vX.Y.Z` for a
module in a subdirectory, and `go get` will not find any other form.

## Releasing

1. Bump the version in the file named above. Commit to `main` here.
2. Wait for **Mirror SDKs** to finish.
3. In qopanza-sdks: `git tag python-v0.1.0 && git push origin python-v0.1.0`
4. Watch the workflow.
5. **Install from the registry, on a machine that has never seen the
   source, and run the quickstart.**

Step 5 is the one that gets skipped and the one that matters. It catches
the whole class of bug where everything passes locally because the file is
on disk anyway — a path missing from `files`, `include`, `spec.files` or
`<None Include>`. A package that installs and then fails on import is
worse than no package, because someone found you and then found you
broken.

## Credentials

Six of the seven registries use **trusted publishing**: GitHub proves the
workflow's identity by OIDC and the registry issues a token that lives
minutes. Nothing long-lived is stored, so there is nothing to leak.

Each needs a one-time registration naming owner `isingomajoel2023`,
repository `qopanza-sdks`, the workflow filename, and environment
`release`. The exact form is in each workflow's header comment.

**Maven Central is the exception** — no OIDC, so `qopanza-sdks` needs four
repository secrets: `CENTRAL_TOKEN_USERNAME`, `CENTRAL_TOKEN_PASSWORD`,
`GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`.

`GPG_PRIVATE_KEY` is the ability to sign releases as Gsente LLC and is the
most valuable secret in either repository. Restrict the `release`
environment to protected tags so nothing from a fork can reach it.

Signing key fingerprint, for anyone verifying a signature:

```
9DF1 0248 1289 CBAA 42F5  2CE5 35C0 F2B5 E692 E7FE
Gsente LLC <security@qopanza.com>
```

## Two first-release exceptions

- **npm** cannot have a trusted publisher until the package exists.
  Publish `0.1.0` once from a laptop with `npm publish --access public`
  and 2FA, then configure the trusted publisher and let CI do the rest.
  That applies twice: once for `qopanza` (`typescript/`, `publish-npm.yml`)
  and once for `qopanza-mcp` (`mcp-server/`, `publish-mcp.yml`).
- **Maven Central** uploads with `autoPublish=false`. The workflow leaves
  the bundle validated but unpublished; you press Publish in the portal.
  A published version can never be replaced, so look at the first one.

## Do not edit qopanza-sdks directly

It is overwritten by the next mirror run. Changes go in `sdks/` here. The
only things that originate in the mirror are git tags.
