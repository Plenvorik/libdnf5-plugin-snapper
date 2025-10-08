// Copyright (C) 2025 Andre Herrlich <plenvorik@gmail.com>
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file test_advanced_features.cpp
 * @brief Advanced unit tests for configuration, security, and performance
 */

#include <catch2/catch.hpp>
#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <set>

TEST_CASE("Configuration parsing simulation", "[config][advanced]") {
    SECTION("INI-style boolean parsing") {
        auto parse_boolean = [](const std::string& value) -> std::pair<bool, bool> {
            std::string lower_value = value;
            std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(), ::tolower);

            bool valid = true;
            bool result = false;

            if (lower_value == "true" || lower_value == "1" ||
                lower_value == "yes" || lower_value == "on") {
                result = true;
            } else if (lower_value == "false" || lower_value == "0" ||
                       lower_value == "no" || lower_value == "off") {
                result = false;
            } else {
                valid = false;
            }

            return {result, valid};
        };

        // Valid cases
        auto [result1, valid1] = parse_boolean("true");
        REQUIRE(result1 == true);
        REQUIRE(valid1 == true);

        auto [result2, valid2] = parse_boolean("FALSE");
        REQUIRE(result2 == false);
        REQUIRE(valid2 == true);

        auto [result3, valid3] = parse_boolean("1");
        REQUIRE(result3 == true);
        REQUIRE(valid3 == true);

        // Invalid cases
        auto [result4, valid4] = parse_boolean("maybe");
        REQUIRE(valid4 == false);

        auto [result5, valid5] = parse_boolean("");
        REQUIRE(valid5 == false);
    }

    SECTION("Advanced pattern list parsing") {
        auto parse_pattern_list = [](const std::string& input) -> std::vector<std::string> {
            std::vector<std::string> patterns;
            std::string current;

            for (size_t i = 0; i < input.length(); ++i) {
                char c = input[i];

                if (c == ',' || c == ' ' || c == '\t' || c == '\n') {
                    if (!current.empty()) {
                        // Trim whitespace from current
                        current.erase(0, current.find_first_not_of(" \t\n\r"));
                        current.erase(current.find_last_not_of(" \t\n\r") + 1);

                        if (!current.empty()) {
                            patterns.push_back(current);
                        }
                        current.clear();
                    }
                } else {
                    current += c;
                }
            }

            // Handle last pattern
            if (!current.empty()) {
                current.erase(0, current.find_first_not_of(" \t\n\r"));
                current.erase(current.find_last_not_of(" \t\n\r") + 1);
                if (!current.empty()) {
                    patterns.push_back(current);
                }
            }

            return patterns;
        };

        // Test various input formats
        auto patterns1 = parse_pattern_list("htop,tree,firefox");
        REQUIRE(patterns1.size() == 3);
        REQUIRE(std::find(patterns1.begin(), patterns1.end(), "htop") != patterns1.end());

        auto patterns2 = parse_pattern_list("  htop , tree   firefox  ");
        REQUIRE(patterns2.size() == 3);

        auto patterns3 = parse_pattern_list("kernel-*,  \n  lib*  \t,  *-dev");
        REQUIRE(patterns3.size() == 3);
        REQUIRE(std::find(patterns3.begin(), patterns3.end(), "kernel-*") != patterns3.end());

        // Edge cases
        auto patterns4 = parse_pattern_list("");
        REQUIRE(patterns4.empty());

        auto patterns5 = parse_pattern_list("   ,  ,  ");
        REQUIRE(patterns5.empty());

        auto patterns6 = parse_pattern_list("single");
        REQUIRE(patterns6.size() == 1);
        REQUIRE(patterns6[0] == "single");
    }

    SECTION("Configuration defaults and validation") {
        struct Config {
            bool enabled{true};
            bool dryrun{false};
            std::string snapper_config{"root"};
            std::string cleanup_algorithm{"number"};
            std::string root_prefix{"/"};
        };

        auto validate_config = [](Config& config) -> std::vector<std::string> {
            std::vector<std::string> errors;

            if (config.snapper_config.empty()) {
                config.snapper_config = "root";
                errors.push_back("Empty snapper_config, using 'root'");
            }

            if (config.root_prefix.empty()) {
                config.root_prefix = "/";
                errors.push_back("Empty root_prefix, using '/'");
            }

            // Validate cleanup algorithm
            std::set<std::string> valid_algorithms = {"number", "timeline", "empty-pre-post"};
            if (valid_algorithms.find(config.cleanup_algorithm) == valid_algorithms.end()) {
                if (!config.cleanup_algorithm.empty()) {
                    errors.push_back("Unknown cleanup algorithm: " + config.cleanup_algorithm);
                } else {
                    config.cleanup_algorithm = "number";
                    errors.push_back("Empty cleanup algorithm, using 'number'");
                }
            }

            return errors;
        };

        // Test valid config
        Config valid_config;
        auto errors1 = validate_config(valid_config);
        REQUIRE(errors1.empty());

        // Test invalid config gets corrected
        Config invalid_config;
        invalid_config.snapper_config = "";
        invalid_config.root_prefix = "";
        invalid_config.cleanup_algorithm = "invalid";

        auto errors2 = validate_config(invalid_config);
        REQUIRE(errors2.size() == 3);
        REQUIRE(invalid_config.snapper_config == "root");
        REQUIRE(invalid_config.root_prefix == "/");
    }
}

TEST_CASE("Security validation simulation", "[security][advanced]") {
    SECTION("Pattern security validation") {
        auto is_safe_pattern = [](const std::string& pattern) -> std::pair<bool, std::string> {
            // Check pattern length
            if (pattern.length() > 256) {
                return {false, "Pattern too long"};
            }

            // Check for valid characters (alphanumeric, wildcards, common package chars)
            for (char c : pattern) {
                if (!std::isalnum(c) && c != '*' && c != '?' && c != '.' &&
                    c != '_' && c != '-' && c != '+') {
                    return {false, "Invalid character: " + std::string(1, c)};
                }
            }

            // Check for dangerous patterns
            if (pattern.find("**") != std::string::npos) {
                return {false, "Double wildcard not allowed"};
            }

            if (pattern.find("*+") != std::string::npos) {
                return {false, "Dangerous regex pattern"};
            }

            // Check wildcard density
            size_t wildcard_count = std::count_if(pattern.begin(), pattern.end(),
                                                 [](char c) { return c == '*' || c == '?'; });
            if (pattern.length() > 10 && (wildcard_count * 3) > pattern.length()) {
                return {false, "Too many wildcards"};
            }

            return {true, ""};
        };

        // Valid patterns
        auto [safe1, msg1] = is_safe_pattern("htop");
        REQUIRE(safe1 == true);

        auto [safe2, msg2] = is_safe_pattern("kernel-*");
        REQUIRE(safe2 == true);

        auto [safe3, msg3] = is_safe_pattern("lib*.so");
        REQUIRE(safe3 == true);

        // Invalid patterns
        auto [safe4, msg4] = is_safe_pattern("**");
        REQUIRE(safe4 == false);
        REQUIRE(msg4 == "Double wildcard not allowed");

        auto [safe5, msg5] = is_safe_pattern("*+");
        REQUIRE(safe5 == false);
        REQUIRE(msg5 == "Dangerous regex pattern");

        auto [safe6, msg6] = is_safe_pattern("test@pattern");  // Use @ instead of null char
        REQUIRE(safe6 == false);

        auto [safe7, msg7] = is_safe_pattern(std::string(300, 'a'));
        REQUIRE(safe7 == false);
        REQUIRE(msg7 == "Pattern too long");
    }

    SECTION("Input sanitization") {
        auto sanitize_string = [](const std::string& input, size_t max_length = 256) -> std::string {
            std::string result;
            result.reserve(std::min(input.length(), max_length));

            for (size_t i = 0; i < input.length() && result.length() < max_length; ++i) {
                char c = input[i];
                // Only allow printable ASCII characters (excluding control chars and whitespace except space)
                if (c >= 33 && c <= 126) {  // Printable chars, excluding space and below
                    result += c;
                }
            }

            return result;
        };

        REQUIRE(sanitize_string("normal_string") == "normal_string");
        REQUIRE(sanitize_string("test\x01with\nnull") == "testwithnull");  // \x01 and \n get filtered
        REQUIRE(sanitize_string("test\x01\x02\x03") == "test");

        std::string long_input(1000, 'a');
        REQUIRE(sanitize_string(long_input).length() == 256);
    }

    SECTION("Metadata validation") {
        auto validate_metadata_field = [](const std::string& field, const std::string& value) -> bool {
            if (value.empty()) return false;
            if (value.length() > 256) return false;

            // Field-specific validation
            if (field == "sudo" || field == "user") {
                // Username validation: alphanumeric, underscore, dash only
                return std::all_of(value.begin(), value.end(),
                                 [](char c) { return std::isalnum(c) || c == '_' || c == '-'; });
            }

            if (field == "ops") {
                // Operations format: i2,r1,u3 etc.
                return std::all_of(value.begin(), value.end(),
                                 [](char c) { return std::isalnum(c) || c == ',' || c == '-'; });
            }

            // Default: printable ASCII only
            return std::all_of(value.begin(), value.end(),
                             [](char c) { return c >= 32 && c <= 126; });
        };

        // Valid metadata
        REQUIRE(validate_metadata_field("sudo", "username") == true);
        REQUIRE(validate_metadata_field("sudo", "user_123") == true);
        REQUIRE(validate_metadata_field("sudo", "user-name") == true);
        REQUIRE(validate_metadata_field("ops", "i2,r1,u3") == true);

        // Invalid metadata
        REQUIRE(validate_metadata_field("sudo", "") == false);
        REQUIRE(validate_metadata_field("sudo", "user@domain") == false);
        REQUIRE(validate_metadata_field("sudo", "user name") == false);
        REQUIRE(validate_metadata_field("sudo", std::string(300, 'a')) == false);
    }
}

TEST_CASE("Performance optimization simulation", "[performance][advanced]") {
    SECTION("Pattern matching performance") {
        auto simple_wildcard_match = [](const std::string& name, const std::string& pattern) -> bool {
            if (pattern == "*") return true;
            if (pattern == name) return true;

            if (pattern.back() == '*') {
                std::string prefix = pattern.substr(0, pattern.length() - 1);
                return name.length() >= prefix.length() &&
                       name.substr(0, prefix.length()) == prefix;
            }

            if (pattern.front() == '*') {
                std::string suffix = pattern.substr(1);
                return name.length() >= suffix.length() &&
                       name.substr(name.length() - suffix.length()) == suffix;
            }

            return false;
        };

        // Generate test data
        std::vector<std::string> packages;
        for (int i = 0; i < 1000; ++i) {
            packages.push_back("package-" + std::to_string(i));
            packages.push_back("lib-" + std::to_string(i));
            packages.push_back("kernel-module-" + std::to_string(i));
        }

        std::vector<std::string> patterns = {"*", "lib-*", "kernel-*", "*-debuginfo"};

        auto start = std::chrono::high_resolution_clock::now();

        size_t total_matches = 0;
        for (const auto& pkg : packages) {
            for (const auto& pattern : patterns) {
                if (simple_wildcard_match(pkg, pattern)) {
                    total_matches++;
                }
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        REQUIRE(total_matches > 0);
        REQUIRE(duration.count() < 50000);  // Should complete in <50ms

        // Verify some expected matches
        REQUIRE(simple_wildcard_match("lib-123", "lib-*") == true);
        REQUIRE(simple_wildcard_match("kernel-module-456", "kernel-*") == true);
        REQUIRE(simple_wildcard_match("anything", "*") == true);
    }

    SECTION("Cache simulation") {
        // Simulate a simple pattern cache
        struct PatternCache {
            std::map<std::string, bool> cache;
            size_t hits{0};
            size_t misses{0};

            bool lookup(const std::string& key, const std::function<bool()>& compute) {
                auto it = cache.find(key);
                if (it != cache.end()) {
                    hits++;
                    return it->second;
                }

                misses++;
                bool result = compute();
                cache[key] = result;
                return result;
            }

            double hit_ratio() const {
                size_t total = hits + misses;
                return total > 0 ? static_cast<double>(hits) / total : 0.0;
            }
        };

        PatternCache cache;

        // Simulate repeated pattern matching
        std::vector<std::string> packages = {"htop", "tree", "kernel-core", "lib-ssl"};
        std::vector<std::string> patterns = {"*", "kernel-*", "lib-*"};

        // First pass - all cache misses
        for (const auto& pkg : packages) {
            for (const auto& pattern : patterns) {
                std::string key = pkg + ":" + pattern;
                cache.lookup(key, [&]() {
                    return pkg.find("kernel") == 0 && pattern == "kernel-*";
                });
            }
        }

        size_t first_misses = cache.misses;

        // Second pass - should have cache hits
        for (const auto& pkg : packages) {
            for (const auto& pattern : patterns) {
                std::string key = pkg + ":" + pattern;
                cache.lookup(key, [&]() {
                    return pkg.find("kernel") == 0 && pattern == "kernel-*";
                });
            }
        }

        REQUIRE(cache.hits > 0);
        REQUIRE(cache.misses == first_misses);  // No new misses
        REQUIRE(cache.hit_ratio() >= 0.5);     // At least 50% hit ratio
    }

    SECTION("Memory usage optimization") {
        // Test efficient data structures
        struct CompactFilterStats {
            uint16_t include_patterns{0};
            uint16_t exclude_patterns{0};
            uint16_t important_patterns{0};
            uint16_t cached_regexes{0};
            uint32_t cache_hits{0};
            uint32_t cache_misses{0};
            bool has_wildcard_include{false};
        };

        CompactFilterStats stats;
        stats.include_patterns = 10;
        stats.exclude_patterns = 5;
        stats.cache_hits = 1000;

        // Verify the struct is reasonably sized
        REQUIRE(sizeof(CompactFilterStats) <= 32);  // Should be compact

        // Test string interning simulation
        std::vector<std::string> common_patterns = {
            "*", "kernel-*", "lib*", "*-debuginfo", "*-devel"
        };

        std::map<std::string, size_t> pattern_usage;

        // Simulate pattern usage counting
        for (int i = 0; i < 100; ++i) {
            for (const auto& pattern : common_patterns) {
                pattern_usage[pattern]++;
            }
        }

        // Most common patterns should be heavily used
        REQUIRE(pattern_usage["*"] == 100);
        REQUIRE(pattern_usage["kernel-*"] == 100);

        // This could inform caching strategies
        size_t total_usage = 0;
        for (const auto& [pattern, count] : pattern_usage) {
            total_usage += count;
        }
        REQUIRE(total_usage == 500);  // 5 patterns * 100 iterations
    }
}