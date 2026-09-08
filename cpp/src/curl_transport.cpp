#include "qopanza/curl_transport.hpp"

#include <curl/curl.h>

#include <stdexcept>

namespace qopanza {

namespace {

size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

}  // namespace

CurlHttpTransport::CurlHttpTransport(long timeout_ms) : timeout_ms_(timeout_ms) {}

HttpResponse CurlHttpTransport::request(
    const std::string& method,
    const std::string& url,
    const std::string& body,
    const std::map<std::string, std::string>& headers) {
    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        throw std::runtime_error("Failed to initialize curl handle");
    }

    std::string response_body;
    struct curl_slist* header_list = nullptr;
    for (const auto& [key, value] : headers) {
        header_list = curl_slist_append(header_list, (key + ": " + value).c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms_);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.c_str());

    if (!body.empty()) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    }

    CURLcode result = curl_easy_perform(curl);

    long status_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);

    curl_slist_free_all(header_list);
    curl_easy_cleanup(curl);

    if (result != CURLE_OK) {
        throw std::runtime_error(std::string("HTTP request failed: ") + curl_easy_strerror(result));
    }

    return HttpResponse{status_code, response_body};
}

}  // namespace qopanza
