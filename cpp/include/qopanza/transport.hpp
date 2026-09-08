#pragma once

#include <map>
#include <memory>
#include <string>

namespace qopanza {

struct HttpResponse {
    long status_code = 0;
    std::string body;
};

/// Seam between QopanzaClient and the actual HTTP stack — lets tests
/// substitute a fake transport instead of hitting the network, the same
/// approach the Python/TypeScript/C# SDKs use (fake the HTTP boundary,
/// not the whole client).
class HttpTransport {
public:
    virtual ~HttpTransport() = default;

    virtual HttpResponse request(
        const std::string& method,
        const std::string& url,
        const std::string& body,
        const std::map<std::string, std::string>& headers) = 0;
};

}  // namespace qopanza
