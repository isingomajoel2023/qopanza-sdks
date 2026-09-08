#include <gtest/gtest.h>

#include <functional>

#include "qopanza/client.hpp"

using namespace qopanza;

namespace {

/// Fake HttpTransport for testing QopanzaClient without a live
/// server — analogous to faking `fetch`/`HttpMessageHandler` in the
/// TypeScript/C# SDKs' test suites.
class FakeHttpTransport : public HttpTransport {
public:
    using Responder = std::function<HttpResponse(const std::string&, const std::string&, const std::string&)>;

    explicit FakeHttpTransport(Responder responder) : responder_(std::move(responder)) {}

    HttpResponse request(
        const std::string& method,
        const std::string& url,
        const std::string& body,
        const std::map<std::string, std::string>& headers) override {
        last_url = url;
        last_body = body;
        last_headers = headers;
        return responder_(method, url, body);
    }

    std::string last_url;
    std::string last_body;
    std::map<std::string, std::string> last_headers;

private:
    Responder responder_;
};

}  // namespace

TEST(QopanzaApiError, CarriesStatusCodeAndDetail) {
    QopanzaApiError err(404, "Key not found");
    EXPECT_EQ(err.status_code(), 404);
    EXPECT_EQ(err.detail(), "Key not found");
    EXPECT_NE(std::string(err.what()).find("404"), std::string::npos);
}

TEST(QopanzaClient, GetKeyStripsTrailingSlashAndSendsApiKeyHeader) {
    auto transport = std::make_shared<FakeHttpTransport>([](const std::string&, const std::string&, const std::string&) {
        return HttpResponse{
            200,
            R"({"id":"key-1","purpose":"kem","algorithm":"ML-KEM-768","backend":"liboqs",)"
            R"("public_key":"cHVi","created_at":"2026-01-01T00:00:00Z","label":null,"expires_at":null})",
        };
    });
    QopanzaClient client("http://localhost:8000/", "test-key", transport);

    KeyResponse key = client.get_key("key-1");

    EXPECT_EQ(transport->last_url, "http://localhost:8000/v1/keys/key-1");
    EXPECT_EQ(transport->last_headers.at("X-API-Key"), "test-key");
    EXPECT_EQ(key.id, "key-1");
    EXPECT_FALSE(key.label.has_value());
}

TEST(QopanzaClient, NonSuccessStatusThrowsWithDetailFromBody) {
    auto transport = std::make_shared<FakeHttpTransport>([](const std::string&, const std::string&, const std::string&) {
        return HttpResponse{404, R"({"detail":"Key not found"})"};
    });
    QopanzaClient client("http://localhost:8000", "test-key", transport);

    try {
        client.get_key("missing");
        FAIL() << "expected QopanzaApiError";
    } catch (const QopanzaApiError& err) {
        EXPECT_EQ(err.status_code(), 404);
        EXPECT_EQ(err.detail(), "Key not found");
    }
}

TEST(QopanzaClient, EncryptThenDecryptRoundTripsThroughWireFormatMapping) {
    auto transport = std::make_shared<FakeHttpTransport>(
        [](const std::string&, const std::string& url, const std::string& body) -> HttpResponse {
            if (url.find("/encrypt") != std::string::npos) {
                EXPECT_NE(body.find(R"("key_id":"key-1")"), std::string::npos);
                return HttpResponse{
                    200,
                    R"({"key_id":"key-1","ciphertext_kem":"a2Vt","ciphertext_payload":"cGF5bG9hZA==",)"
                    R"("nonce":"bm9uY2U=","backend":"liboqs"})",
                };
            }
            if (url.find("/decrypt") != std::string::npos) {
                EXPECT_NE(body.find(R"("ciphertext_kem":"a2Vt")"), std::string::npos);
                return HttpResponse{200, R"({"plaintext":"aGVsbG8="})"};
            }
            throw std::runtime_error("unexpected request to " + url);
        });
    QopanzaClient client("http://localhost:8000", "test-key", transport);

    std::vector<unsigned char> plaintext{'h', 'e', 'l', 'l', 'o'};
    EncryptResult enc = client.encrypt("key-1", plaintext);
    EXPECT_EQ(enc.key_id, "key-1");
    EXPECT_EQ(enc.ciphertext_kem, "a2Vt");

    std::vector<unsigned char> decrypted = client.decrypt(enc);
    EXPECT_EQ(decrypted, plaintext);
}
