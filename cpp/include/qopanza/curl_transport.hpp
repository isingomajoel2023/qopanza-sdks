#pragma once

#include "qopanza/transport.hpp"

namespace qopanza {

/// Real HttpTransport backed by libcurl's easy interface.
class CurlHttpTransport : public HttpTransport {
public:
    explicit CurlHttpTransport(long timeout_ms = 15000);

    HttpResponse request(
        const std::string& method,
        const std::string& url,
        const std::string& body,
        const std::map<std::string, std::string>& headers) override;

private:
    long timeout_ms_;
};

}  // namespace qopanza
