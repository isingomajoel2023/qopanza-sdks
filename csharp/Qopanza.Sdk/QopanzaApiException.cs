namespace Qopanza.Sdk;

/// <summary>Thrown when the Qopanza API returns a non-2xx response.</summary>
public sealed class QopanzaApiException : Exception
{
    public int StatusCode { get; }
    public string ResponseBody { get; }

    public QopanzaApiException(int statusCode, string responseBody)
        : base($"Qopanza API error [{statusCode}]: {responseBody}")
    {
        StatusCode = statusCode;
        ResponseBody = responseBody;
    }
}
