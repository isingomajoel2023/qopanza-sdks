cmake_minimum_required(VERSION 3.16)
# Copyright 2026 Gsente LLC. Apache-2.0 — see LICENSE beside this file.
# CMake's project() has no licence field, so the LICENSE file is the
# only place that lives.
project(qopanza
  VERSION 0.1.0
  DESCRIPTION "C++ client for the Qopanza API"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(QOPANZA_BUILD_EXAMPLES "Build the quickstart example" ON)
option(QOPANZA_BUILD_TESTS "Build the test suite" ON)

find_package(CURL REQUIRED)
find_package(nlohmann_json REQUIRED)

add_library(qopanza
    src/client.cpp
    src/curl_transport.cpp
)
target_include_directories(qopanza PUBLIC include)
target_link_libraries(qopanza PUBLIC CURL::libcurl nlohmann_json::nlohmann_json)

if(QOPANZA_BUILD_EXAMPLES)
    add_executable(quickstart examples/quickstart.cpp)
    target_link_libraries(quickstart PRIVATE qopanza)
endif()

if(QOPANZA_BUILD_TESTS)
    find_package(GTest REQUIRED)
    enable_testing()

    add_executable(qopanza_tests
        tests/base64_test.cpp
        tests/client_test.cpp
    )
    target_link_libraries(qopanza_tests PRIVATE qopanza GTest::gtest GTest::gtest_main)
    add_test(NAME qopanza_tests COMMAND qopanza_tests)
endif()
