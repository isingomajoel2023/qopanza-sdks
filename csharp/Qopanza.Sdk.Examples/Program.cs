// Run against a local `docker compose up` stack:
//   cd sdks/csharp && dotnet run --project Qopanza.Sdk.Examples
//
// Signs up for a fresh account to get a real API key first — this SDK
// covers the crypto/analyze endpoints only, account signup isn't part of
// it yet, so this example makes that one call directly with HttpClient.

using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Qopanza.Sdk;

const string BaseUrl = "http://localhost:8000";

async Task<string> SignUpAndGetApiKeyAsync()
{
    using var http = new HttpClient();
    var response = await http.PostAsJsonAsync(
        $"{BaseUrl}/v1/accounts",
        new { email = "quickstart-csharp@example.com", password = "quickstart-password-1" });

    if (response.StatusCode == System.Net.HttpStatusCode.Conflict)
    {
        throw new InvalidOperationException(
            "Account already exists — this quickstart signs up fresh each run. " +
            "Change the email above or delete the account first.");
    }
    response.EnsureSuccessStatusCode();

    var body = await response.Content.ReadAsStringAsync();
    using var doc = JsonDocument.Parse(body);
    return doc.RootElement.GetProperty("api_key").GetString()!;
}

var apiKey = await SignUpAndGetApiKeyAsync();
using var client = new QopanzaClient(BaseUrl, apiKey);

Console.WriteLine("== Key encapsulation (encrypt/decrypt) ==");
var kemKey = await client.CreateKeyAsync("kem", "quickstart-kem");
Console.WriteLine($"Created KEM key: {kemKey.Id}");

var plaintext = Encoding.UTF8.GetBytes("hello quantum-safe world");
var enc = await client.EncryptAsync(kemKey.Id, plaintext);
var decrypted = await client.DecryptAsync(enc);
Console.WriteLine($"Round-trip OK: {Encoding.UTF8.GetString(decrypted) == Encoding.UTF8.GetString(plaintext)}");

Console.WriteLine("\n== Signatures ==");
var sigKey = await client.CreateKeyAsync("signature", "quickstart-sig");
var message = Encoding.UTF8.GetBytes("order-42-confirmed");
var signed = await client.SignAsync(sigKey.Id, message);
var valid = await client.VerifyAsync(sigKey.Id, message, signed.Signature);
Console.WriteLine($"Signature valid: {valid}");

Console.WriteLine("\n== AI security analysis ==");
var report = await client.AnalyzeAsync(new { algorithms_in_use = new[] { "RSA-2048" }, key_reuse_count = 3 });
Console.WriteLine($"Summary: {report.Summary}");
foreach (var finding in report.Findings)
{
    Console.WriteLine($"  [{finding.Severity}] {finding.RuleId}: {finding.Title}");
}
