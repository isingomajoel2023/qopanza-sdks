using System.Net;
using System.Text;
using Qopanza.Sdk;
using Xunit;

namespace Qopanza.Sdk.Tests;

public class QopanzaClientTests
{
    [Fact]
    public async Task GetKey_StripsTrailingSlashFromBaseUrl()
    {
        var handler = FakeHttpMessageHandler.ReturningJson(HttpStatusCode.OK, """
            {"id":"key-1","purpose":"kem","algorithm":"ML-KEM-768","backend":"liboqs",
             "public_key":"cHVi","created_at":"2026-01-01T00:00:00Z","label":null,"expires_at":null}
            """);
        using var http = new HttpClient(handler);
        using var client = new QopanzaClient(http, "http://localhost:8000/", apiKey: "test-key");

        var key = await client.GetKeyAsync("key-1");

        Assert.Equal("http://localhost:8000/v1/keys/key-1", handler.LastRequest!.RequestUri!.ToString());
        Assert.Equal("key-1", key.Id);
        Assert.Equal("test-key", handler.LastRequest.Headers.GetValues("X-API-Key").Single());
    }

    [Fact]
    public async Task GetKey_NonSuccessStatus_ThrowsWithDetailFromBody()
    {
        var handler = FakeHttpMessageHandler.ReturningJson(HttpStatusCode.NotFound, """{"detail":"Key not found"}""");
        using var http = new HttpClient(handler);
        using var client = new QopanzaClient(http, apiKey: "test-key");

        var ex = await Assert.ThrowsAsync<QopanzaApiException>(() => client.GetKeyAsync("missing"));

        Assert.Equal(404, ex.StatusCode);
        Assert.Equal("Key not found", ex.ResponseBody);
    }

    [Fact]
    public async Task EncryptThenDecrypt_RoundTripsThroughWireFormatMapping()
    {
        var handler = new FakeHttpMessageHandler(async request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/encrypt"))
            {
                var body = await request.Content!.ReadAsStringAsync();
                Assert.Contains("\"key_id\":\"key-1\"", body);
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("""
                        {"key_id":"key-1","ciphertext_kem":"a2Vt","ciphertext_payload":"cGF5bG9hZA==",
                         "nonce":"bm9uY2U=","backend":"liboqs"}
                        """),
                };
            }
            if (path.EndsWith("/decrypt"))
            {
                var body = await request.Content!.ReadAsStringAsync();
                Assert.Contains("\"ciphertext_kem\":\"a2Vt\"", body);
                var plaintextB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("hello"));
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent($$"""{"plaintext":"{{plaintextB64}}"}"""),
                };
            }
            throw new InvalidOperationException($"unexpected request to {path}");
        });
        using var http = new HttpClient(handler);
        using var client = new QopanzaClient(http, apiKey: "test-key");

        var enc = await client.EncryptAsync("key-1", Encoding.UTF8.GetBytes("hello"));
        Assert.Equal("key-1", enc.KeyId);
        Assert.Equal("a2Vt", enc.CiphertextKem);

        var plaintext = await client.DecryptAsync(enc);
        Assert.Equal("hello", Encoding.UTF8.GetString(plaintext));
    }
}
