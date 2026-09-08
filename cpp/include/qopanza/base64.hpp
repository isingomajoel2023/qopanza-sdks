#pragma once

// Minimal, dependency-free base64 codec. The wire protocol only needs
// encode (for plaintext/message bytes going out) and decode (for
// plaintext bytes coming back from /decrypt) — not a general-purpose
// streaming codec, so this stays small and self-contained rather than
// pulling in a library for two functions.

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace qopanza::base64 {

inline std::string encode(const std::vector<unsigned char>& data) {
    static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 3 <= data.size()) {
        uint32_t chunk = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8) |
                         static_cast<uint32_t>(data[i + 2]);
        out.push_back(table[(chunk >> 18) & 0x3F]);
        out.push_back(table[(chunk >> 12) & 0x3F]);
        out.push_back(table[(chunk >> 6) & 0x3F]);
        out.push_back(table[chunk & 0x3F]);
        i += 3;
    }

    size_t remaining = data.size() - i;
    if (remaining == 1) {
        uint32_t chunk = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(table[(chunk >> 18) & 0x3F]);
        out.push_back(table[(chunk >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (remaining == 2) {
        uint32_t chunk = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8);
        out.push_back(table[(chunk >> 18) & 0x3F]);
        out.push_back(table[(chunk >> 12) & 0x3F]);
        out.push_back(table[(chunk >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

inline std::string encode(const std::string& data) {
    return encode(std::vector<unsigned char>(data.begin(), data.end()));
}

inline std::vector<unsigned char> decode(const std::string& input) {
    static int8_t reverse_table[256];
    static bool initialized = false;
    if (!initialized) {
        std::fill(std::begin(reverse_table), std::end(reverse_table), static_cast<int8_t>(-1));
        static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; ++i) {
            reverse_table[static_cast<unsigned char>(table[i])] = static_cast<int8_t>(i);
        }
        initialized = true;
    }

    std::vector<unsigned char> out;
    out.reserve((input.size() / 4) * 3);

    uint32_t buffer = 0;
    int bits_collected = 0;
    for (char c : input) {
        if (c == '=' || c == '\n' || c == '\r') {
            continue;
        }
        int8_t value = reverse_table[static_cast<unsigned char>(c)];
        if (value < 0) {
            throw std::invalid_argument("Invalid base64 character");
        }
        buffer = (buffer << 6) | static_cast<uint32_t>(value);
        bits_collected += 6;
        if (bits_collected >= 8) {
            bits_collected -= 8;
            out.push_back(static_cast<unsigned char>((buffer >> bits_collected) & 0xFF));
        }
    }
    return out;
}

}  // namespace qopanza::base64
