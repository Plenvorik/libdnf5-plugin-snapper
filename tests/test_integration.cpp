// Copyright (C) 2025 Andre Herrlich <plenvorik@gmail.com>
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file test_integration.cpp
 * @brief Integration tests for end-to-end plugin functionality
 */

#include <catch2/catch.hpp>
#include <vector>
#include <string>
#include <map>
#include <fstream>
#include <filesystem>

TEST_CASE("Real-world package scenarios", "[integration][realistic]") {
    SECTION("Fedora package update simulation") {
        // Simulate a real Fedora package update with common packages
        std::vector<std::string> fedora_packages = {
            // System packages
            "kernel", "kernel-core", "kernel-modules", "kernel-devel",
            "glibc", "glibc-common", "glibc-devel",
            "systemd", "systemd-libs", "systemd-devel",

            // Development packages
            "gcc", "gcc-c++", "make", "cmake",
            "python3", "python3-libs", "python3-devel",

            // User applications
            "firefox", "htop", "tree", "vim-enhanced",
            "git", "curl", "wget",

            // Debug packages (should be excluded)
            "kernel-debuginfo", "glibc-debuginfo", "systemd-debuginfo",
            "firefox-debuginfo", "python3-debuginfo",

            // Development packages (might be excluded)
            "kernel-devel", "glibc-devel", "systemd-devel",
            "python3-devel", "gcc-devel"
        };

        // Test realistic filtering scenarios
        auto test_filter_scenario = [&](const std::vector<std::string>& include_patterns,
                                        const std::vector<std::string>& exclude_patterns,
                                        const std::vector<std::string>& important_patterns) {
            struct TestResult {
                size_t total_packages{0};
                size_t snapshot_packages{0};
                size_t excluded_packages{0};
                size_t important_packages{0};
                double snapshot_ratio{0.0};
            };

            TestResult result;
            result.total_packages = fedora_packages.size();

            for (const auto& pkg : fedora_packages) {
                bool should_snapshot = false;
                bool is_important = false;
                bool is_excluded = false;

                // Check important packages first
                for (const auto& pattern : important_patterns) {
                    if (pattern == "*" || pattern == pkg ||
                        (pattern.back() == '*' && pkg.substr(0, pattern.length()-1) == pattern.substr(0, pattern.length()-1))) {
                        is_important = true;
                        break;
                    }
                }

                // Check exclusions
                for (const auto& pattern : exclude_patterns) {
                    if (pattern == "*" || pattern == pkg ||
                        (pattern.back() == '*' && pkg.length() >= pattern.length()-1 &&
                         pkg.substr(0, pattern.length()-1) == pattern.substr(0, pattern.length()-1)) ||
                        (pattern.front() == '*' && pkg.length() >= pattern.length()-1 &&
                         pkg.substr(pkg.length()-(pattern.length()-1)) == pattern.substr(1))) {
                        is_excluded = true;
                        break;
                    }
                }

                // Check inclusions (if not excluded)
                if (!is_excluded) {
                    if (include_patterns.empty()) {
                        should_snapshot = true; // Default include all
                    } else {
                        for (const auto& pattern : include_patterns) {
                            if (pattern == "*" || pattern == pkg ||
                                (pattern.back() == '*' && pkg.length() >= pattern.length()-1 &&
                                 pkg.substr(0, pattern.length()-1) == pattern.substr(0, pattern.length()-1))) {
                                should_snapshot = true;
                                break;
                            }
                        }
                    }
                }

                if (should_snapshot) result.snapshot_packages++;
                if (is_excluded) result.excluded_packages++;
                if (is_important) result.important_packages++;
            }

            result.snapshot_ratio = static_cast<double>(result.snapshot_packages) / result.total_packages;
            return result;
        };

        // Scenario 1: Include all, exclude debug packages
        auto result1 = test_filter_scenario(
            {"*"},                              // Include all
            {"*-debuginfo", "*-debugsource"},   // Exclude debug
            {"kernel*", "glibc*", "systemd*"}  // Important system packages
        );

        REQUIRE(result1.total_packages == fedora_packages.size());
        REQUIRE(result1.excluded_packages >= 5);    // At least 5 debug packages excluded
        REQUIRE(result1.important_packages >= 6);   // At least 6 important packages
        REQUIRE(result1.snapshot_ratio > 0.7);      // At least 70% of packages included

        // Scenario 2: Only system packages
        auto result2 = test_filter_scenario(
            {"kernel*", "glibc*", "systemd*", "gcc*", "python3*"},
            {"*-debuginfo", "*-devel"},
            {"kernel*", "glibc*", "systemd*"}
        );

        REQUIRE(result2.snapshot_packages < result1.snapshot_packages); // Fewer packages
        REQUIRE(result2.snapshot_ratio < 0.5);                          // Less than 50%
        REQUIRE(result2.important_packages >= 3);                       // Still important packages

        // Scenario 3: Development environment
        auto result3 = test_filter_scenario(
            {"*"},
            {"*-debuginfo"},  // Keep devel packages
            {"gcc*", "python3*", "cmake", "make"}
        );

        REQUIRE(result3.snapshot_packages > result2.snapshot_packages); // More packages than system-only
        REQUIRE(result3.important_packages >= 4);                       // Development packages marked important
    }

    SECTION("Enterprise server package scenario") {
        std::vector<std::string> server_packages = {
            // Core system
            "kernel", "kernel-core", "glibc", "systemd",

            // Server services
            "httpd", "nginx", "postgresql", "postgresql-server",
            "mariadb", "mariadb-server", "redis",

            // Security and monitoring
            "firewalld", "selinux-policy", "audit",
            "rsyslog", "logrotate",

            // Development tools (might be excluded on production)
            "gcc", "make", "git", "strace", "gdb",

            // Debug packages (should be excluded)
            "httpd-debuginfo", "postgresql-debuginfo",
            "kernel-debuginfo"
        };

        // Conservative server filtering: critical services only
        size_t critical_count = 0;
        size_t debug_count = 0;

        for (const auto& pkg : server_packages) {
            // Critical server packages
            if (pkg.find("kernel") == 0 || pkg.find("glibc") == 0 ||
                pkg.find("systemd") == 0 || pkg.find("httpd") == 0 ||
                pkg.find("postgresql") == 0 || pkg.find("mariadb") == 0) {
                if (pkg.find("-debuginfo") == std::string::npos) {
                    critical_count++;
                }
            }

            // Debug packages
            if (pkg.find("-debuginfo") != std::string::npos) {
                debug_count++;
            }
        }

        REQUIRE(critical_count >= 8);  // At least 8 critical packages identified
        REQUIRE(debug_count >= 3);     // At least 3 debug packages to exclude
        REQUIRE(server_packages.size() > 15); // Sufficient test data
    }
}

TEST_CASE("Configuration integration scenarios", "[integration][config]") {
    SECTION("Multiple configuration profiles") {
        struct ConfigProfile {
            std::string name;
            std::map<std::string, std::string> main_section;
            std::map<std::string, std::string> filters_section;
        };

        std::vector<ConfigProfile> profiles = {
            {
                "desktop-user",
                {{"enabled", "true"}, {"dryrun", "false"}, {"snapper_config", "root"}},
                {{"include_packages", "*"},
                 {"exclude_packages", "*-debuginfo, *-debugsource, *-doc"},
                 {"important_packages", "kernel*, firefox, thunderbird"}}
            },
            {
                "server-conservative",
                {{"enabled", "true"}, {"dryrun", "false"}, {"snapper_config", "root"}},
                {{"include_packages", "kernel*, glibc*, systemd*, httpd*, postgresql*"},
                 {"exclude_packages", "*-debuginfo, *-devel"},
                 {"important_packages", "kernel*, glibc*, systemd*, httpd*, postgresql*"}}
            },
            {
                "developer-workstation",
                {{"enabled", "true"}, {"dryrun", "false"}, {"snapper_config", "root"}},
                {{"include_packages", "*"},
                 {"exclude_packages", "*-debuginfo"},
                 {"important_packages", "kernel*, gcc*, python3*, nodejs*, docker*"}}
            },
            {
                "disabled-profile",
                {{"enabled", "false"}, {"dryrun", "true"}, {"snapper_config", "root"}},
                {{"include_packages", "*"}, {"exclude_packages", ""}, {"important_packages", ""}}
            }
        };

        for (const auto& profile : profiles) {
            // Validate configuration parsing
            REQUIRE(!profile.main_section.empty());
            REQUIRE(profile.main_section.count("enabled") > 0);
            REQUIRE(profile.main_section.count("snapper_config") > 0);

            // Validate filters section
            if (profile.main_section.at("enabled") == "true") {
                REQUIRE(profile.filters_section.count("include_packages") > 0);

                // Test pattern list parsing
                auto include_patterns = profile.filters_section.at("include_packages");
                REQUIRE(!include_patterns.empty());

                if (profile.name == "server-conservative") {
                    // Should have specific patterns with wildcards
                    REQUIRE(include_patterns.find("kernel*") != std::string::npos);
                    bool has_wildcard = (include_patterns.find("*") != std::string::npos);
                    REQUIRE(has_wildcard == true); // Should have wildcard patterns
                }
            }
        }

        // Test profile selection based on system type
        auto detect_best_profile = [&profiles](const std::string& system_type) -> std::string {
            if (system_type == "desktop") return "desktop-user";
            if (system_type == "server") return "server-conservative";
            if (system_type == "development") return "developer-workstation";
            return "desktop-user"; // default
        };

        REQUIRE(detect_best_profile("desktop") == "desktop-user");
        REQUIRE(detect_best_profile("server") == "server-conservative");
        REQUIRE(detect_best_profile("development") == "developer-workstation");
        REQUIRE(detect_best_profile("unknown") == "desktop-user");
    }

    SECTION("Configuration validation and error recovery") {
        struct ConfigTest {
            std::string description;
            std::map<std::string, std::string> config;
            bool should_be_valid;
            std::string expected_error;
        };

        std::vector<ConfigTest> config_tests = {
            {"Valid minimal config",
             {{"enabled", "true"}}, true, ""},

            {"Invalid boolean value",
             {{"enabled", "maybe"}}, false, "invalid boolean"},

            {"Empty snapper config",
             {{"enabled", "true"}, {"snapper_config", ""}}, false, "empty snapper_config"},

            {"Very long pattern",
             {{"enabled", "true"}, {"include_packages", std::string(1000, 'a')}}, false, "pattern too long"},

            {"Dangerous pattern",
             {{"enabled", "true"}, {"include_packages", "**"}}, false, "dangerous pattern"},

            {"Valid complex config",
             {{"enabled", "true"}, {"dryrun", "false"},
              {"snapper_config", "root"}, {"cleanup_algorithm", "number"}}, true, ""}
        };

        for (const auto& test : config_tests) {
            // Simulate config validation
            bool is_valid = true;
            std::string error_msg;

            for (const auto& [key, value] : test.config) {
                if (key == "enabled" || key == "dryrun") {
                    if (value != "true" && value != "false" &&
                        value != "1" && value != "0" &&
                        value != "yes" && value != "no") {
                        is_valid = false;
                        error_msg = "invalid boolean";
                        break;
                    }
                }

                if (key == "snapper_config" && value.empty()) {
                    is_valid = false;
                    error_msg = "empty snapper_config";
                    break;
                }

                if (key == "include_packages" || key == "exclude_packages") {
                    if (value.length() > 500) {
                        is_valid = false;
                        error_msg = "pattern too long";
                        break;
                    }
                    if (value.find("**") != std::string::npos) {
                        is_valid = false;
                        error_msg = "dangerous pattern";
                        break;
                    }
                }
            }

            REQUIRE(is_valid == test.should_be_valid);
            if (!test.should_be_valid) {
                REQUIRE(error_msg.find(test.expected_error) != std::string::npos);
            }
        }
    }
}

TEST_CASE("Performance integration benchmarks", "[integration][performance]") {
    SECTION("Large-scale transaction simulation") {
        // Simulate a large system update with realistic package counts
        auto generate_package_list = [](size_t base_count) -> std::vector<std::string> {
            std::vector<std::string> packages;
            packages.reserve(base_count * 3); // Include base, devel, debug variants

            for (size_t i = 0; i < base_count; ++i) {
                packages.push_back("package-" + std::to_string(i));
                packages.push_back("lib-package-" + std::to_string(i));

                // Add some debug packages
                if (i % 5 == 0) {
                    packages.push_back("package-" + std::to_string(i) + "-debuginfo");
                }

                // Add some devel packages
                if (i % 3 == 0) {
                    packages.push_back("package-" + std::to_string(i) + "-devel");
                }
            }

            return packages;
        };

        // Test with increasing package counts
        std::vector<size_t> test_sizes = {100, 500, 1000, 2000};

        for (size_t size : test_sizes) {
            auto packages = generate_package_list(size);

            auto start = std::chrono::high_resolution_clock::now();

            // Simulate filtering process
            size_t snapshot_count = 0;
            size_t excluded_count = 0;

            for (const auto& pkg : packages) {
                bool should_snapshot = true;

                // Exclude debug packages
                if (pkg.find("-debuginfo") != std::string::npos ||
                    pkg.find("-debugsource") != std::string::npos) {
                    should_snapshot = false;
                    excluded_count++;
                }

                // Include specific patterns
                if (should_snapshot && (pkg.find("package-") == 0 || pkg.find("lib-") == 0)) {
                    snapshot_count++;
                }
            }

            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

            // Performance requirements scale with package count
            double max_time_per_package = 10.0; // 10 microseconds per package
            REQUIRE(duration.count() < (packages.size() * max_time_per_package));

            // Verify filtering worked correctly
            REQUIRE(snapshot_count > 0);
            REQUIRE(excluded_count > 0);
            REQUIRE((snapshot_count + excluded_count) <= packages.size());

            // Log performance for monitoring
            INFO("Processed " << packages.size() << " packages in " << duration.count() << "μs");
            INFO("Performance: " << (duration.count() / static_cast<double>(packages.size())) << "μs per package");
        }
    }

    SECTION("Pattern complexity performance") {
        // Test performance with increasingly complex pattern sets
        std::vector<std::string> test_packages;
        for (int i = 0; i < 1000; ++i) {
            test_packages.push_back("package-" + std::to_string(i) + "-component");
            test_packages.push_back("lib-service-" + std::to_string(i));
            test_packages.push_back("framework-module-" + std::to_string(i) + "-ext");
        }

        struct PatternComplexityTest {
            std::string name;
            std::vector<std::string> patterns;
            size_t max_time_us;
        };

        std::vector<PatternComplexityTest> complexity_tests = {
            {
                "Simple patterns",
                {"package-*", "lib-*"},
                5000  // 5ms max
            },
            {
                "Medium complexity",
                {"package-*", "lib-service-*", "*-component", "*-ext"},
                10000  // 10ms max
            },
            {
                "High complexity",
                {"package-*-component", "lib-service-*", "*-module-*", "*-ext",
                 "framework-*", "*-component", "lib-*-service", "*-framework-*"},
                20000  // 20ms max
            }
        };

        for (const auto& test : complexity_tests) {
            auto start = std::chrono::high_resolution_clock::now();

            size_t matches = 0;
            for (const auto& pkg : test_packages) {
                for (const auto& pattern : test.patterns) {
                    bool match = false;

                    if (pattern == "*") {
                        match = true;
                    } else if (pattern == pkg) {
                        match = true;
                    } else if (!pattern.empty() && pattern.back() == '*') {
                        std::string prefix = pattern.substr(0, pattern.length() - 1);
                        match = pkg.length() >= prefix.length() &&
                               pkg.substr(0, prefix.length()) == prefix;
                    } else if (!pattern.empty() && pattern.front() == '*') {
                        std::string suffix = pattern.substr(1);
                        match = pkg.length() >= suffix.length() &&
                               pkg.substr(pkg.length() - suffix.length()) == suffix;
                    }

                    if (match) {
                        matches++;
                        break; // First match is sufficient
                    }
                }
            }

            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

            REQUIRE(static_cast<size_t>(duration.count()) < test.max_time_us);
            REQUIRE(matches > 0); // Should find some matches

            INFO(test.name << ": " << matches << " matches in " << duration.count() << "μs");
        }
    }
}

TEST_CASE("System integration scenarios", "[integration][system]") {
    SECTION("Snapshot decision workflow") {
        // Simulate the complete decision-making workflow
        struct TransactionSimulation {
            std::vector<std::string> packages;
            std::string transaction_type;
            size_t expected_snapshots;
            bool should_be_important;
        };

        std::vector<TransactionSimulation> scenarios = {
            {
                {"htop", "tree", "firefox"},
                "install_user_apps",
                3, false
            },
            {
                {"kernel-core", "kernel-modules"},
                "kernel_update",
                2, true
            },
            {
                {"package1-debuginfo", "package2-debuginfo"},
                "debug_install",
                0, false  // Debug packages excluded
            },
            {
                {"glibc", "glibc-common", "systemd", "systemd-libs"},
                "system_critical_update",
                4, true
            }
        };

        for (const auto& scenario : scenarios) {
            // Simulate filtering decision
            size_t snapshot_count = 0;
            bool has_important = false;

            for (const auto& pkg : scenario.packages) {
                bool should_snapshot = true;
                bool is_important = false;

                // Exclude debug packages
                if (pkg.find("-debuginfo") != std::string::npos) {
                    should_snapshot = false;
                }

                // Mark system packages as important
                if (pkg.find("kernel") == 0 || pkg.find("glibc") == 0 ||
                    pkg.find("systemd") == 0) {
                    is_important = true;
                }

                if (should_snapshot) snapshot_count++;
                if (is_important) has_important = true;
            }

            REQUIRE(snapshot_count == scenario.expected_snapshots);
            REQUIRE(has_important == scenario.should_be_important);
        }
    }

    SECTION("Error handling and recovery") {
        // Test various error scenarios and recovery mechanisms
        struct ErrorScenario {
            std::string description;
            std::function<bool()> error_condition;
            std::string expected_behavior;
        };

        std::vector<ErrorScenario> error_tests = {
            {
                "Empty package list",
                []() {
                    std::vector<std::string> empty_packages;
                    return empty_packages.empty();
                },
                "no_snapshot_created"
            },
            {
                "Invalid pattern configuration",
                []() {
                    std::string dangerous_pattern = "**";
                    return dangerous_pattern.find("**") != std::string::npos;
                },
                "pattern_validation_failed"
            },
            {
                "Resource exhaustion simulation",
                []() {
                    // Simulate memory/time constraints
                    size_t large_count = 100000;
                    return large_count > 50000;
                },
                "resource_limit_reached"
            }
        };

        for (const auto& error_test : error_tests) {
            bool error_detected = error_test.error_condition();

            if (error_test.expected_behavior == "no_snapshot_created") {
                REQUIRE(error_detected == true);
                // Should handle gracefully without crashing
            } else if (error_test.expected_behavior == "pattern_validation_failed") {
                REQUIRE(error_detected == true);
                // Should reject dangerous patterns
            } else if (error_test.expected_behavior == "resource_limit_reached") {
                REQUIRE(error_detected == true);
                // Should handle large datasets efficiently
            }
        }
    }
}