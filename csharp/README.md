# Qopanza.Sdk (C# / .NET)

C#/.NET client for the Qopanza API. Targets .NET 8, zero third-party
runtime dependencies — built on `System.Net.Http.HttpClient` and
`System.Text.Json` from the BCL only.

## Install (local dev)

```bash
cd sdks/csharp
dotnet build
```

To reference it from another .NET project once built, add a project
reference to `Qopanza.Sdk/Qopanza.Sdk.csproj` (a NuGet package
hasn't been published yet).

## Usage

This SDK covers the crypto/analyze endpoints only — get a real API key by
signing up first (account signup isn't part of the SDK yet):

```csharp
using var http = new HttpClient();
var signupResponse = await http.PostAsJsonAsync("http://localhost:8000/v1/accounts",
    new { email = "you@example.com", password = "a-real-password" });
var signup = await signupResponse.Content.ReadFromJsonAsync<JsonElement>();
var apiKey = signup.GetProperty("api_key").GetString(); // shown once — store it
```

```csharp
using Qopanza.Sdk;

using var client = new QopanzaClient("http://localhost:8000", apiKey);

// Generate a KEM keypair
var key = await client.CreateKeyAsync("kem", "order-service-kem");

// Encrypt / decrypt
var enc = await client.EncryptAsync(key.Id, Encoding.UTF8.GetBytes("hello quantum-safe world"));
var plaintext = await client.DecryptAsync(enc);
Console.WriteLine(Encoding.UTF8.GetString(plaintext)); // "hello quantum-safe world"

// Signatures
var sigKey = await client.CreateKeyAsync("signature", "order-service-sig");
var message = Encoding.UTF8.GetBytes("order-42-confirmed");
var signed = await client.SignAsync(sigKey.Id, message);
var valid = await client.VerifyAsync(sigKey.Id, message, signed.Signature);

// AI security analysis
var report = await client.AnalyzeAsync(new { algorithms_in_use = new[] { "RSA-2048" }, key_reuse_count = 3 });
foreach (var finding in report.Findings)
{
    Console.WriteLine($"{finding.Severity} {finding.Title}");
}
```

Errors from the API surface as `QopanzaApiException`, carrying
`StatusCode` and `ResponseBody`:

```csharp
try
{
    await client.GetKeyAsync("does-not-exist");
}
catch (QopanzaApiException ex)
{
    Console.Error.WriteLine($"{ex.StatusCode}: {ex.ResponseBody}");
}
```

For advanced scenarios (custom retry/proxy `HttpClient` configuration, or
injecting a fake handler in tests), use the
`QopanzaClient(HttpClient, string, string?)` constructor overload —
in that case, disposing the client does not dispose the `HttpClient` you
passed in, since you own its lifetime.

## Running the examples and tests

```bash
# Quickstart, against a local `docker compose up` stack:
dotnet run --project Qopanza.Sdk.Examples

# Tests — fake the HTTP layer, no live server required:
dotnet test
```

See `Qopanza.Sdk.Examples/Program.cs` for the full quickstart and
`Qopanza.Sdk.Tests/` for the test suite.
