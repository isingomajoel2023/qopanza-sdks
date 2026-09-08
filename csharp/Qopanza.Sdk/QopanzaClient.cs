using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace Qopanza.Sdk;

/// <summary>
/// C#/.NET client for the Qopanza API.
///
/// Covers the crypto/analyze endpoints only (keys, encrypt, decrypt,
/// sign, verify, analyze) — account signup, billing, usage, support, and
/// webhooks aren't part of this SDK yet, same scoping as the Python,
/// Java, and TypeScript SDKs. Get a real API key by signing up first;
/// see examples/Quickstart for a worked example.
/// </summary>
public sealed class QopanzaClient : IDisposable
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        PropertyNamingPolicy = null, // wire DTOs already declare exact snake_case names
    };

    private readonly HttpClient _http;
    private readonly string _baseUrl;
    private readonly bool _ownsHttpClient;

    /// <param name="baseUrl">API base URL, e.g. "http://localhost:8000".</param>
    /// <param name="apiKey">Your API key (from account signup).</param>
    /// <param name="timeout">Request timeout; defaults to 15 seconds.</param>
    public QopanzaClient(string baseUrl = "http://localhost:8000", string? apiKey = null, TimeSpan? timeout = null)
        : this(new HttpClient { Timeout = timeout ?? TimeSpan.FromSeconds(15) }, baseUrl, apiKey, ownsHttpClient: true)
    {
    }

    /// <summary>
    /// Advanced constructor for injecting a custom <see cref="HttpClient"/>
    /// (e.g. one built on a test <see cref="HttpMessageHandler"/>). The
    /// caller owns disposal of <paramref name="httpClient"/> in this case.
    /// </summary>
    public QopanzaClient(HttpClient httpClient, string baseUrl = "http://localhost:8000", string? apiKey = null)
        : this(httpClient, baseUrl, apiKey, ownsHttpClient: false)
    {
    }

    private QopanzaClient(HttpClient httpClient, string baseUrl, string? apiKey, bool ownsHttpClient)
    {
        _http = httpClient;
        _baseUrl = baseUrl.TrimEnd('/') + "/v1";
        _ownsHttpClient = ownsHttpClient;
        if (!string.IsNullOrEmpty(apiKey))
        {
            _http.DefaultRequestHeaders.Remove("X-API-Key");
            _http.DefaultRequestHeaders.Add("X-API-Key", apiKey);
        }
    }

    // -- Keys ---------------------------------------------------------------

    public async Task<KeyResponse> CreateKeyAsync(string purpose, string? label = null, CancellationToken ct = default)
    {
        var wire = await RequestAsync<KeyResponseWire>(HttpMethod.Post, "/keys", new { purpose, label }, ct)
            .ConfigureAwait(false);
        return wire.ToPublic();
    }

    public async Task<KeyResponse> GetKeyAsync(string keyId, CancellationToken ct = default)
    {
        var wire = await RequestAsync<KeyResponseWire>(HttpMethod.Get, $"/keys/{keyId}", null, ct).ConfigureAwait(false);
        return wire.ToPublic();
    }

    // -- Encrypt / Decrypt ----------------------------------------------------

    public async Task<EncryptResult> EncryptAsync(string keyId, byte[] plaintext, CancellationToken ct = default)
    {
        var wire = await RequestAsync<EncryptResponseWire>(
            HttpMethod.Post,
            "/encrypt",
            new { key_id = keyId, plaintext = Convert.ToBase64String(plaintext) },
            ct
        ).ConfigureAwait(false);
        return wire.ToPublic();
    }

    public async Task<byte[]> DecryptAsync(EncryptResult enc, CancellationToken ct = default)
    {
        var wire = await RequestAsync<DecryptResponseWire>(
            HttpMethod.Post,
            "/decrypt",
            new
            {
                key_id = enc.KeyId,
                ciphertext_kem = enc.CiphertextKem,
                ciphertext_payload = enc.CiphertextPayload,
                nonce = enc.Nonce,
            },
            ct
        ).ConfigureAwait(false);
        return Convert.FromBase64String(wire.Plaintext);
    }

    // -- Sign / Verify ----------------------------------------------------------

    public async Task<SignResult> SignAsync(string keyId, byte[] message, CancellationToken ct = default)
    {
        var wire = await RequestAsync<SignResponseWire>(
            HttpMethod.Post,
            "/sign",
            new { key_id = keyId, message = Convert.ToBase64String(message) },
            ct
        ).ConfigureAwait(false);
        return wire.ToPublic();
    }

    public async Task<bool> VerifyAsync(string keyId, byte[] message, string signature, CancellationToken ct = default)
    {
        var wire = await RequestAsync<VerifyResponseWire>(
            HttpMethod.Post,
            "/verify",
            new { key_id = keyId, message = Convert.ToBase64String(message), signature },
            ct
        ).ConfigureAwait(false);
        return wire.Valid;
    }

    // -- AI analysis ------------------------------------------------------------

    public async Task<AnalyzeResult> AnalyzeAsync(object context, CancellationToken ct = default)
    {
        var wire = await RequestAsync<AnalyzeResponseWire>(HttpMethod.Post, "/analyze", new { context }, ct)
            .ConfigureAwait(false);
        return wire.ToPublic();
    }

    // -- internals ----------------------------------------------------------------

    private async Task<T> RequestAsync<T>(HttpMethod method, string path, object? body, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, _baseUrl + path);
        if (body is not null)
        {
            var json = JsonSerializer.Serialize(body, SerializerOptions);
            request.Content = new StringContent(json, Encoding.UTF8);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new QopanzaApiException((int)response.StatusCode, ExtractDetail(text));
        }

        return JsonSerializer.Deserialize<T>(text, SerializerOptions)
            ?? throw new QopanzaApiException((int)response.StatusCode, "Empty response body");
    }

    private static string ExtractDetail(string responseText)
    {
        try
        {
            using var doc = JsonDocument.Parse(responseText);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("detail", out var detail))
            {
                return detail.ValueKind == JsonValueKind.String ? detail.GetString()! : detail.GetRawText();
            }
        }
        catch (JsonException)
        {
            // not JSON — fall through and return the raw body
        }
        return responseText;
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }
}
