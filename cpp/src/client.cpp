#include "qopanza/client.hpp"

#include "qopanza/base64.hpp"
#include "qopanza/curl_transport.hpp"

namespace qopanza {

namespace {

std::string strip_trailing_slash(const std::string& s) {
    if (!s.empty() && s.back() == '/') {
        return s.substr(0, s.size() - 1);
    }
    return s;
}

std::string extract_detail(const std::string& body) {
    try {
        auto parsed = nlohmann::json::parse(body);
        if (parsed.contains("detail")) {
            const auto& detail = parsed["detail"];
            return detail.is_string() ? detail.get<std::string>() : detail.dump();
        }
    } catch (const nlohmann::json::parse_error&) {
        // not JSON — fall through and return the raw body
    }
    return body;
}

}  // namespace

QopanzaClient::QopanzaClient(std::string base_url, std::string api_key, long timeout_ms)
    : base_url_(strip_trailing_slash(base_url) + "/v1"),
      api_key_(std::move(api_key)),
      transport_(std::make_shared<CurlHttpTransport>(timeout_ms)) {}

QopanzaClient::QopanzaClient(std::string base_url, std::string api_key, std::shared_ptr<HttpTransport> transport)
    : base_url_(strip_trailing_slash(base_url) + "/v1"), api_key_(std::move(api_key)), transport_(std::move(transport)) {}

nlohmann::json QopanzaClient::request(const std::string& method, const std::string& path, const nlohmann::json* body) {
    std::map<std::string, std::string> headers{{"Content-Type", "application/json"}};
    if (!api_key_.empty()) {
        headers["X-API-Key"] = api_key_;
    }

    std::string body_str = body != nullptr ? body->dump() : "";
    HttpResponse resp = transport_->request(method, base_url_ + path, body_str, headers);

    if (resp.status_code < 200 || resp.status_code >= 300) {
        throw QopanzaApiError(static_cast<int>(resp.status_code), extract_detail(resp.body));
    }

    if (resp.body.empty()) {
        return nlohmann::json::object();
    }
    return nlohmann::json::parse(resp.body);
}

KeyResponse QopanzaClient::create_key(const std::string& purpose, const std::optional<std::string>& label) {
    nlohmann::json body{{"purpose", purpose}, {"label", label.has_value() ? nlohmann::json(*label) : nullptr}};
    nlohmann::json resp = request("POST", "/keys", &body);

    KeyResponse key;
    key.id = resp.at("id").get<std::string>();
    key.purpose = resp.at("purpose").get<std::string>();
    key.algorithm = resp.at("algorithm").get<std::string>();
    key.backend = resp.at("backend").get<std::string>();
    key.public_key = resp.at("public_key").get<std::string>();
    key.created_at = resp.at("created_at").get<std::string>();
    if (!resp.at("label").is_null()) key.label = resp.at("label").get<std::string>();
    if (!resp.at("expires_at").is_null()) key.expires_at = resp.at("expires_at").get<std::string>();
    return key;
}

KeyResponse QopanzaClient::get_key(const std::string& key_id) {
    nlohmann::json resp = request("GET", "/keys/" + key_id, nullptr);

    KeyResponse key;
    key.id = resp.at("id").get<std::string>();
    key.purpose = resp.at("purpose").get<std::string>();
    key.algorithm = resp.at("algorithm").get<std::string>();
    key.backend = resp.at("backend").get<std::string>();
    key.public_key = resp.at("public_key").get<std::string>();
    key.created_at = resp.at("created_at").get<std::string>();
    if (!resp.at("label").is_null()) key.label = resp.at("label").get<std::string>();
    if (!resp.at("expires_at").is_null()) key.expires_at = resp.at("expires_at").get<std::string>();
    return key;
}

EncryptResult QopanzaClient::encrypt(const std::string& key_id, const std::vector<unsigned char>& plaintext) {
    nlohmann::json body{{"key_id", key_id}, {"plaintext", base64::encode(plaintext)}};
    nlohmann::json resp = request("POST", "/encrypt", &body);

    return EncryptResult{
        resp.at("key_id").get<std::string>(),
        resp.at("ciphertext_kem").get<std::string>(),
        resp.at("ciphertext_payload").get<std::string>(),
        resp.at("nonce").get<std::string>(),
        resp.at("backend").get<std::string>(),
    };
}

std::vector<unsigned char> QopanzaClient::decrypt(const EncryptResult& enc) {
    nlohmann::json body{
        {"key_id", enc.key_id},
        {"ciphertext_kem", enc.ciphertext_kem},
        {"ciphertext_payload", enc.ciphertext_payload},
        {"nonce", enc.nonce},
    };
    nlohmann::json resp = request("POST", "/decrypt", &body);
    return base64::decode(resp.at("plaintext").get<std::string>());
}

SignResult QopanzaClient::sign(const std::string& key_id, const std::vector<unsigned char>& message) {
    nlohmann::json body{{"key_id", key_id}, {"message", base64::encode(message)}};
    nlohmann::json resp = request("POST", "/sign", &body);

    return SignResult{
        resp.at("key_id").get<std::string>(),
        resp.at("signature").get<std::string>(),
        resp.at("backend").get<std::string>(),
    };
}

bool QopanzaClient::verify(
    const std::string& key_id, const std::vector<unsigned char>& message, const std::string& signature) {
    nlohmann::json body{{"key_id", key_id}, {"message", base64::encode(message)}, {"signature", signature}};
    nlohmann::json resp = request("POST", "/verify", &body);
    return resp.at("valid").get<bool>();
}

AnalyzeResult QopanzaClient::analyze(const nlohmann::json& context) {
    nlohmann::json body{{"context", context}};
    nlohmann::json resp = request("POST", "/analyze", &body);

    AnalyzeResult result;
    result.summary = resp.at("summary").get<std::string>();
    result.generated_by = resp.at("generated_by").get<std::string>();
    for (const auto& f : resp.at("findings")) {
        result.findings.push_back(AnalysisFinding{
            f.at("severity").get<std::string>(),
            f.at("rule_id").get<std::string>(),
            f.at("title").get<std::string>(),
            f.at("detail").get<std::string>(),
            f.at("recommendation").get<std::string>(),
        });
    }
    return result;
}

}  // namespace qopanza
