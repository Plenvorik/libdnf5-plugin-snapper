// Copyright (C) 2025 Andre Herrlich <plenvorik@gmail.com>
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file test_basic_functionality.cpp
 * @brief Basic functionality tests for infrastructure validation
 */

#include <catch2/catch.hpp>
#include <string>
#include <vector>
#include <algorithm>

TEST_CASE("Basic C++ functionality", "[basic]") {
    SECTION("String operations") {
        std::string test_string = "libdnf5-plugin-snapper";
        REQUIRE(test_string.find("snapper") != std::string::npos);
        REQUIRE(test_string.length() > 0);
    }

    SECTION("Vector operations") {
        std::vector<int> numbers = {1, 2, 3, 4, 5};
        REQUIRE(numbers.size() == 5);
        REQUIRE(numbers[0] == 1);
        REQUIRE(numbers[4] == 5);
    }

    SECTION("Algorithm functionality") {
        std::vector<std::string> packages = {"htop", "tree", "firefox", "kernel-core"};

        auto it = std::find(packages.begin(), packages.end(), "htop");
        REQUIRE(it != packages.end());

        auto count = std::count_if(packages.begin(), packages.end(),
                                  [](const std::string& pkg) { return pkg.find("kernel") != std::string::npos; });
        REQUIRE(count == 1);
    }
}

TEST_CASE("C++20 features", "[basic][cpp20]") {
    SECTION("Constexpr functionality") {
        constexpr auto lambda_result = []() constexpr { return 42; }();
        REQUIRE(lambda_result == 42);
    }

    SECTION("Structured bindings") {
        std::pair<std::string, int> package_info{"htop", 123};
        auto [name, version] = package_info;

        REQUIRE(name == "htop");
        REQUIRE(version == 123);
    }
}

TEST_CASE("Pattern matching simulation", "[basic][patterns]") {
    SECTION("Simple wildcard simulation") {
        auto matches_pattern = [](const std::string& name, const std::string& pattern) {
            if (pattern == "*") return true;
            if (pattern == name) return true;
            if (pattern.back() == '*') {
                std::string prefix = pattern.substr(0, pattern.length() - 1);
                return name.substr(0, prefix.length()) == prefix;
            }
            return false;
        };

        REQUIRE(matches_pattern("htop", "*") == true);
        REQUIRE(matches_pattern("htop", "htop") == true);
        REQUIRE(matches_pattern("kernel-core", "kernel-*") == true);
        REQUIRE(matches_pattern("htop", "tree") == false);
        REQUIRE(matches_pattern("htop", "kernel-*") == false);
    }

    SECTION("Package filtering simulation") {
        std::vector<std::string> packages = {"htop", "tree", "kernel-core", "htop-debuginfo"};
        std::vector<std::string> include_patterns = {"*"};
        std::vector<std::string> exclude_patterns = {"*-debuginfo"};

        auto should_include = [&](const std::string& pkg) {
            // Check exclusions first
            for (const auto& exclude : exclude_patterns) {
                if (exclude.back() == '*') {
                    std::string suffix = exclude.substr(1);
                    if (pkg.length() >= suffix.length() &&
                        pkg.substr(pkg.length() - suffix.length()) == suffix) {
                        return false;
                    }
                }
            }

            // Check inclusions
            for (const auto& include : include_patterns) {
                if (include == "*") return true;
            }
            return false;
        };

        REQUIRE(should_include("htop") == true);
        REQUIRE(should_include("tree") == true);
        REQUIRE(should_include("kernel-core") == true);
        REQUIRE(should_include("htop-debuginfo") == false);
    }
}

TEST_CASE("Configuration parsing simulation", "[basic][config]") {
    SECTION("Boolean parsing") {
        auto parse_boolean = [](const std::string& value) -> bool {
            std::string lower_value = value;
            std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(), ::tolower);

            return lower_value == "true" || lower_value == "1" ||
                   lower_value == "yes" || lower_value == "on";
        };

        REQUIRE(parse_boolean("true") == true);
        REQUIRE(parse_boolean("TRUE") == true);
        REQUIRE(parse_boolean("1") == true);
        REQUIRE(parse_boolean("yes") == true);
        REQUIRE(parse_boolean("false") == false);
        REQUIRE(parse_boolean("0") == false);
        REQUIRE(parse_boolean("invalid") == false);
    }

    SECTION("Pattern list parsing") {
        auto parse_patterns = [](const std::string& input) -> std::vector<std::string> {
            std::vector<std::string> patterns;
            std::string current;

            for (char c : input) {
                if (c == ',' || c == ' ') {
                    if (!current.empty()) {
                        patterns.push_back(current);
                        current.clear();
                    }
                } else {
                    current += c;
                }
            }

            if (!current.empty()) {
                patterns.push_back(current);
            }

            return patterns;
        };

        auto patterns = parse_patterns("htop,tree firefox,kernel-*");
        REQUIRE(patterns.size() >= 3);
        REQUIRE(std::find(patterns.begin(), patterns.end(), "htop") != patterns.end());
        REQUIRE(std::find(patterns.begin(), patterns.end(), "tree") != patterns.end());
    }
}

TEST_CASE("Error handling simulation", "[basic][errors]") {
    SECTION("Exception safety") {
        REQUIRE_NOTHROW([]() {
            std::vector<std::string> test_data;
            test_data.push_back("test");
            test_data.clear();
        }());
    }

    SECTION("Bounds checking") {
        std::vector<int> numbers = {1, 2, 3};

        REQUIRE_NOTHROW([&]() {
            if (numbers.size() > 2) {
                int value = numbers[2];  // Valid access
                REQUIRE(value == 3);
            }
        }());
    }

    SECTION("String safety") {
        REQUIRE_NOTHROW([]() {
            std::string empty;
            std::string test = empty + "test";
            REQUIRE(test == "test");
        }());
    }
}

TEST_CASE("Performance simulation", "[basic][performance]") {
    SECTION("Large data handling") {
        std::vector<std::string> large_package_list;

        // Create 1000 test packages
        for (int i = 0; i < 1000; ++i) {
            large_package_list.push_back("package-" + std::to_string(i));
        }

        auto start = std::chrono::high_resolution_clock::now();

        size_t matches = 0;
        for (const auto& pkg : large_package_list) {
            if (pkg.find("package-") == 0) {
                matches++;
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        REQUIRE(matches == 1000);
        REQUIRE(duration.count() < 10000);  // Should complete in <10ms
    }
}