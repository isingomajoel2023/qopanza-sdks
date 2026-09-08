using Qopanza.Sdk;
using Xunit;

namespace Qopanza.Sdk.Tests;

public class QopanzaApiExceptionTests
{
    [Fact]
    public void CarriesStatusCodeAndBody()
    {
        var ex = new QopanzaApiException(404, "{\"detail\":\"Key not found\"}");

        Assert.Equal(404, ex.StatusCode);
        Assert.Contains("Key not found", ex.ResponseBody);
        Assert.Contains("404", ex.Message);
    }
}
