// Run against a local `docker compose up` stack:
//   cd sdks/cpp && cmake -B build && cmake --build build
//   ./build/quickstart
//
// Signs up for a fresh account to get a real API key first — this SDK
// covers the crypto/analyze endpoints only, account signup isn't part of
// it yet, so this example makes that one call directly with libcurl.

#include <curl/curl.h>

#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

#include "qopanza/client.hpp"

namespace {

const std::string kBaseUrl = "http://localhost:8000";

size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

std::string sign_up_and_get_api_key() {
    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        throw std::runtime_error("Failed to initialize curl");
    }

    nlohmann::json payload{{"email", "quickstart-cpp@example.com"}, {"password", "quickstart-password-1"}};
    std::string body = payload.dump();
    std::string response_body;

    struct curl_slist* headers = curl_slist_append(nullptr, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, (kBaseUrl + "/v1/accounts").c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
    curl_easy_perform(curl);

    long status_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (status_code == 409) {
        throw std::runtime_error(
            "Account already exists — this quickstart signs up fresh each run. "
            "Change the email above or delete the account first.");
    }
    if (status_code < 200 || status_code >= 300) {
        throw std::runtime_error("Signup failed: " + std::to_string(status_code));
    }

    return nlohmann::json::parse(response_body).at("api_key").get<std::string>();
}

}  // namespace

int main() {
    try {
        std::string api_key = sign_up_and_get_api_key();
        qopanza::QopanzaClient client(kBaseUrl, api_key);

        std::cout << "== Key encapsulation (encrypt/decrypt) ==\n";
        auto kem_key = client.create_key("kem", "quickstart-kem");
        std::cout << "Created KEM key: " << kem_key.id << "\n";

        std::string plaintext_str = "hello quantum-safe world";
        std::vector<unsigned char> plaintext(plaintext_str.begin(), plaintext_str.end());
        auto enc = client.encrypt(kem_key.id, plaintext);
        auto decrypted = client.decrypt(enc);
        std::string decrypted_str(decrypted.begin(), decrypted.end());
        std::cout << "Round-trip OK: " << (decrypted_str == plaintext_str ? "true" : "false") << "\n";

        std::cout << "\n== Signatures ==\n";
        auto sig_key = client.create_key("signature", "quickstart-sig");
        std::string message_str = "order-42-confirmed";
        std::vector<unsigned char> message(message_str.begin(), message_str.end());
        auto signed_result = client.sign(sig_key.id, message);
        bool valid = client.verify(sig_key.id, message, signed_result.signature);
        std::cout << "Signature valid: " << (valid ? "true" : "false") << "\n";

        std::cout << "\n== AI security analysis ==\n";
        nlohmann::json context{{"algorithms_in_use", {"RSA-2048"}}, {"key_reuse_count", 3}};
        auto report = client.analyze(context);
        std::cout << "Summary: " << report.summary << "\n";
        for (const auto& finding : report.findings) {
            std::cout << "  [" << finding.severity << "] " << finding.rule_id << ": " << finding.title << "\n";
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
}
