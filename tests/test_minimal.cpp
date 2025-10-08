// Copyright (C) 2025 Andre Herrlich <plenvorik@gmail.com>
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file test_minimal.cpp
 * @brief Minimal test to isolate build issues
 */

#include <catch2/catch.hpp>

TEST_CASE("Minimal test", "[minimal]") {
    REQUIRE(1 + 1 == 2);
}

TEST_CASE("String test", "[minimal]") {
    std::string test = "hello";
    REQUIRE(test == "hello");
}