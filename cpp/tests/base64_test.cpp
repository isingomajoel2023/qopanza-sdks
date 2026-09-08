#include <gtest/gtest.h>

#include "qopanza/base64.hpp"

using qopanza::base64::decode;
using qopanza::base64::encode;

TEST(Base64, EncodesKnownVector) {
    EXPECT_EQ(encode(std::string("hello")), "aGVsbG8=");
}

TEST(Base64, DecodesKnownVector) {
    auto decoded = decode("aGVsbG8=");
    EXPECT_EQ(std::string(decoded.begin(), decoded.end()), "hello");
}

TEST(Base64, RoundTripsArbitraryBytes) {
    std::vector<unsigned char> original{0, 1, 2, 253, 254, 255, 42, 7};
    auto roundtripped = decode(encode(original));
    EXPECT_EQ(roundtripped, original);
}

TEST(Base64, RoundTripsEmptyInput) {
    std::vector<unsigned char> empty;
    EXPECT_EQ(encode(empty), "");
    EXPECT_TRUE(decode("").empty());
}

TEST(Base64, RejectsInvalidCharacter) {
    EXPECT_THROW(decode("not valid base64!!"), std::invalid_argument);
}
