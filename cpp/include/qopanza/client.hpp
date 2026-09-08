#pragma once

// C++ client for the Qopanza API.
//
// Covers the crypto/analyze endpoints only (keys, encrypt, decrypt,
// sign, verify, analyze) — account signup, billing, usage, support, and
// webhooks aren't part of this SDK yet, same scoping as the Python,
// Java, TypeScript, and C# SDKs. Get a real API key by signing up first;
// see examples/quickstart.cpp for a worked example.
//
// Requires C++17. Depends on libcurl (HTTP) and nlohmann/json (JSON).

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "qopanza/transport.hpp"

namespace qopanza {

class QopanzaApiError : public std::runtime_error {
public:
    QopanzaApiError(int status_code, std::string detail)
        : std::runtime_error("[" + std::to_string(status_code) + "] " + detail),
          status_code_(status_code),
          detail_(std::move(detail)) {}

    int status_code() const { return status_code_; }
    const std::string& detail() const { return detail_; }

private:
    int status_code_;
    std::string detail_;
};

struct KeyResponse {
    std::string id;
    std::string purpose;
    std::string algorithm;
    std::string backend;
    std::string public_key;  // base64
    std::string created_at;
    std::optional<std::string> label;
    std::optional<std::string> expires_at;
};

struct EncryptResult {
    std::string key_id;
    std::string ciphertext_kem;      // base64
    std::string ciphertext_payload;  // base64
    std::string nonce;               // base64
    std::string backend;
};

struct SignResult {
    std::string key_id;
    std::string signature;  // base64
    std::string backend;
};

struct AnalysisFinding {
    std::string severity;
    std::string rule_id;
    std::string title;
    std::string detail;
    std::string recommendation;
};

struct AnalyzeResult {
    std::vector<AnalysisFinding> findings;
    std::string summary;
    std::string generated_by;
};

class QopanzaClient {
public:
    /// Real (libcurl-backed) constructor.
    explicit QopanzaClient(
        std::string base_url = "http://localhost:8000",
        std::string api_key = "",
        long timeout_ms = 15000);

    /// Test/advanced constructor — inject any HttpTransport implementation
    /// (e.g. a fake one that returns canned responses without a network
    /// call).
    QopanzaClient(std::string base_url, std::string api_key, std::shared_ptr<HttpTransport> transport);

    KeyResponse create_key(const std::string& purpose, const std::optional<std::string>& label = std::nullopt);
    KeyResponse get_key(const std::string& key_id);

    EncryptResult encrypt(const std::string& key_id, const std::vector<unsigned char>& plaintext);
    std::vector<unsigned char> decrypt(const EncryptResult& enc);

    SignResult sign(const std::string& key_id, const std::vector<unsigned char>& message);
    bool verify(const std::string& key_id, const std::vector<unsigned char>& message, const std::string& signature);

    AnalyzeResult analyze(const nlohmann::json& context);

private:
    std::string base_url_;
    std::string api_key_;
    std::shared_ptr<HttpTransport> transport_;

    nlohmann::json request(const std::string& method, const std::string& path, const nlohmann::json* body);
};

}  // namespace qopanza
