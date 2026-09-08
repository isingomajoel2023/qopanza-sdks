using System.Net;

namespace Qopanza.Sdk.Tests;

/// <summary>
/// A minimal fake <see cref="HttpMessageHandler"/> for testing
/// <c>QopanzaClient</c> without a live server — analogous to faking
/// the global `fetch` in the TypeScript SDK's tests.
/// </summary>
internal sealed class FakeHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, Task<HttpResponseMessage>> _responder;

    public HttpRequestMessage? LastRequest { get; private set; }
    public string? LastRequestBody { get; private set; }

    public FakeHttpMessageHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> responder)
    {
        _responder = responder;
    }

    public static FakeHttpMessageHandler ReturningJson(HttpStatusCode statusCode, string json) =>
        new(_ => Task.FromResult(new HttpResponseMessage(statusCode)
        {
            Content = new StringContent(json),
        }));

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        LastRequest = request;
        LastRequestBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
        return await _responder(request);
    }
}
