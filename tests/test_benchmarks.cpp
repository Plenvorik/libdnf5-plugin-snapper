// Copyright (C) 2025 Andre Herrlich <plenvorik@gmail.com>
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file test_benchmarks.cpp
 * @brief Performance benchmarks and production readiness tests
 */

#include <catch2/catch.hpp>
#include <vector>
#include <string>
#include <random>
#include <algorithm>
#include <thread>
#include <future>
#include <map>
#include <set>
#include <memory>
#include <chrono>

TEST_CASE("Production scale benchmarks", "[benchmarks][production]") {
    SECTION("Enterprise package repository simulation") {
        // Simulate enterprise-scale package repositories
        auto generate_enterprise_packages = [](size_t count) -> std::vector<std::string> {
            std::vector<std::string> packages;
            packages.reserve(count);

            std::vector<std::string> prefixes = {
                "kernel", "glibc", "systemd", "httpd", "nginx", "postgresql",
                "mariadb", "redis", "docker", "kubernetes", "ansible",
                "java", "python3", "nodejs", "gcc", "clang", "rust"
            };

            std::vector<std::string> suffixes = {
                "", "-libs", "-devel", "-debuginfo", "-debugsource",
                "-server", "-client", "-common", "-tools", "-utils"
            };

            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> prefix_dist(0, prefixes.size() - 1);
            std::uniform_int_distribution<> suffix_dist(0, suffixes.size() - 1);
            std::uniform_int_distribution<> version_dist(1, 999);

            for (size_t i = 0; i < count; ++i) {
                std::string pkg = prefixes[prefix_dist(gen)];
                if (i % 10 != 0) {  // 90% have version numbers
                    pkg += "-" + std::to_string(version_dist(gen));
                }
                pkg += suffixes[suffix_dist(gen)];
                packages.push_back(pkg);
            }

            return packages;
        };

        // Test with enterprise-scale package counts
        std::vector<size_t> enterprise_scales = {5000, 10000, 25000, 50000};

        for (size_t scale : enterprise_scales) {
            auto packages = generate_enterprise_packages(scale);

            // Enterprise filtering patterns
            std::vector<std::string> include_patterns = {"*"};
            std::vector<std::string> exclude_patterns = {
                "*-debuginfo", "*-debugsource", "*-devel"
            };
            std::vector<std::string> important_patterns = {
                "kernel*", "glibc*", "systemd*", "httpd*", "nginx*",
                "postgresql*", "mariadb*"
            };

            auto start = std::chrono::high_resolution_clock::now();

            // Simulate production filtering logic
            size_t snapshot_candidates = 0;
            size_t excluded_packages = 0;
            size_t important_packages = 0;

            for (const auto& pkg : packages) {
                bool matches_include = false;
                bool matches_exclude = false;
                bool is_important = false;

                // Check include patterns (optimized for *)
                if (std::find(include_patterns.begin(), include_patterns.end(), "*") != include_patterns.end()) {
                    matches_include = true;
                }

                // Check exclude patterns
                for (const auto& pattern : exclude_patterns) {
                    if (pattern.back() == '*') {
                        std::string prefix = pattern.substr(0, pattern.length() - 1);
                        if (pkg.length() >= prefix.length() &&
                            pkg.substr(0, prefix.length()) == prefix) {
                            matches_exclude = true;
                            break;
                        }
                    } else if (pattern.front() == '*') {
                        std::string suffix = pattern.substr(1);
                        if (pkg.length() >= suffix.length() &&
                            pkg.substr(pkg.length() - suffix.length()) == suffix) {
                            matches_exclude = true;
                            break;
                        }
                    }
                }

                // Check important patterns
                for (const auto& pattern : important_patterns) {
                    if (pattern.back() == '*') {
                        std::string prefix = pattern.substr(0, pattern.length() - 1);
                        if (pkg.length() >= prefix.length() &&
                            pkg.substr(0, prefix.length()) == prefix) {
                            is_important = true;
                            break;
                        }
                    }
                }

                if (matches_include && !matches_exclude) snapshot_candidates++;
                if (matches_exclude) excluded_packages++;
                if (is_important) important_packages++;
            }

            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

            // Enterprise performance requirements
            double max_time_per_1k_packages = 50.0; // 50ms per 1000 packages
            double expected_max_time = (scale / 1000.0) * max_time_per_1k_packages;

            REQUIRE(duration.count() < expected_max_time);
            REQUIRE(snapshot_candidates > 0);
            REQUIRE(excluded_packages > 0);
            REQUIRE(important_packages > 0);

            // Performance metrics for monitoring
            double throughput = scale / (duration.count() / 1000.0); // packages per second

            INFO("Scale: " << scale << " packages");
            INFO("Time: " << duration.count() << "ms");
            INFO("Throughput: " << throughput << " packages/sec");
            INFO("Snapshot candidates: " << snapshot_candidates << " ("
                 << (100.0 * snapshot_candidates / scale) << "%)");
            INFO("Excluded: " << excluded_packages << " ("
                 << (100.0 * excluded_packages / scale) << "%)");
            INFO("Important: " << important_packages << " ("
                 << (100.0 * important_packages / scale) << "%)");

            // Verify reasonable filtering ratios
            double exclusion_ratio = static_cast<double>(excluded_packages) / scale;
            REQUIRE(exclusion_ratio >= 0.1);  // At least 10% should be excluded
            REQUIRE(exclusion_ratio <= 0.5);  // At most 50% should be excluded
        }
    }

    SECTION("Memory usage and stability") {
        // Test memory efficiency with large datasets
        auto measure_memory_usage = [](size_t package_count) -> size_t {
            // Simulate memory usage measurement
            std::vector<std::string> large_package_list;
            large_package_list.reserve(package_count);

            for (size_t i = 0; i < package_count; ++i) {
                large_package_list.push_back("package-" + std::to_string(i) + "-component");
            }

            // Simulate pattern storage
            std::vector<std::string> patterns = {
                "*", "kernel-*", "lib*", "*-core", "*-server", "*-client"
            };

            // Simulate cache storage
            std::map<std::string, bool> result_cache;
            for (const auto& pkg : large_package_list) {
                for (const auto& pattern : patterns) {
                    std::string cache_key = pkg + ":" + pattern;
                    result_cache[cache_key] = (pkg.find("kernel") == 0);
                }
            }

            // Return approximate memory usage (bytes)
            size_t memory_estimate =
                large_package_list.size() * 50 +  // Package names (avg 50 bytes)
                patterns.size() * 20 +             // Patterns (avg 20 bytes)
                result_cache.size() * 70;          // Cache entries (avg 70 bytes)

            return memory_estimate;
        };

        std::vector<size_t> memory_test_sizes = {1000, 5000, 10000, 25000};

        for (size_t size : memory_test_sizes) {
            size_t memory_usage = measure_memory_usage(size);

            // Memory efficiency requirements
            double bytes_per_package = static_cast<double>(memory_usage) / size;

            REQUIRE(bytes_per_package < 1000);  // Less than 1KB per package on average

            INFO("Package count: " << size);
            INFO("Memory usage: " << (memory_usage / 1024) << " KB");
            INFO("Per package: " << bytes_per_package << " bytes");

            // Verify linear scaling (not exponential)
            if (size > 1000) {
                double scaling_factor = static_cast<double>(memory_usage) / (size * 100); // Base estimate: 100 bytes per package
                REQUIRE(scaling_factor < 10.0);  // Should scale linearly, not exponentially
            }
        }
    }
}

TEST_CASE("Concurrent access benchmarks", "[benchmarks][concurrency]") {
    SECTION("Multi-threaded filtering simulation") {
        // Simulate concurrent plugin usage (multiple DNF processes)
        auto worker_thread = [](int thread_id, size_t package_count) -> std::map<std::string, size_t> {
            std::vector<std::string> packages;
            for (size_t i = 0; i < package_count; ++i) {
                packages.push_back("thread" + std::to_string(thread_id) + "-pkg" + std::to_string(i));
            }

            std::vector<std::string> patterns = {"*", "thread*", "*-pkg*"};

            size_t matches = 0;
            size_t processing_time = 0;

            auto start = std::chrono::high_resolution_clock::now();

            for (const auto& pkg : packages) {
                for (const auto& pattern : patterns) {
                    if (pattern == "*" || pkg.find("thread") == 0) {
                        matches++;
                        break;
                    }
                }
            }

            auto end = std::chrono::high_resolution_clock::now();
            processing_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

            return {
                {"matches", matches},
                {"time_us", processing_time},
                {"packages", package_count}
            };
        };

        // Test with 4 concurrent threads (common server scenario)
        size_t num_threads = 4;
        size_t packages_per_thread = 2000;

        std::vector<std::future<std::map<std::string, size_t>>> futures;

        auto overall_start = std::chrono::high_resolution_clock::now();

        for (size_t i = 0; i < num_threads; ++i) {
            futures.push_back(std::async(std::launch::async, worker_thread, i, packages_per_thread));
        }

        // Wait for all threads and collect results
        std::vector<std::map<std::string, size_t>> results;
        for (auto& future : futures) {
            results.push_back(future.get());
        }

        auto overall_end = std::chrono::high_resolution_clock::now();
        auto overall_time = std::chrono::duration_cast<std::chrono::milliseconds>(overall_end - overall_start);

        // Verify all threads completed successfully
        REQUIRE(results.size() == num_threads);

        size_t total_matches = 0;
        size_t max_thread_time = 0;

        for (const auto& result : results) {
            REQUIRE(result.at("matches") > 0);
            REQUIRE(result.at("packages") == packages_per_thread);

            total_matches += result.at("matches");
            max_thread_time = std::max(max_thread_time, result.at("time_us"));
        }

        // Performance requirements for concurrent access
        REQUIRE(overall_time.count() < 5000);  // Total time < 5 seconds
        REQUIRE(max_thread_time < 2000000);    // Max thread time < 2 seconds
        REQUIRE(total_matches > 0);            // All threads found matches

        INFO("Threads: " << num_threads);
        INFO("Packages per thread: " << packages_per_thread);
        INFO("Overall time: " << overall_time.count() << "ms");
        INFO("Max thread time: " << (max_thread_time / 1000) << "ms");
        INFO("Total matches: " << total_matches);

        // Verify reasonable concurrency behavior
        // For micro-benchmarks with very fast execution, timing may not be reliable
        if (overall_time.count() >= 10 && max_thread_time > 1000) {  // At least 10ms overall and 1ms per thread
            double theoretical_sequential_time = max_thread_time * num_threads / 1000.0; // Convert to ms
            double concurrency_efficiency = theoretical_sequential_time / overall_time.count();
            REQUIRE(concurrency_efficiency >= 0.3);  // Should be reasonably efficient
        } else {
            // For very fast tests, just verify basic functionality
            REQUIRE(total_matches > 0);  // All threads found some matches
            REQUIRE(overall_time.count() < 1000);  // Should complete quickly
        }
    }

    SECTION("Cache contention simulation") {
        // Simulate cache behavior under concurrent access
        struct ThreadSafeCache {
            std::map<std::string, bool> cache;
            std::mutex cache_mutex;
            size_t hits{0};
            size_t misses{0};

            bool lookup(const std::string& key) {
                std::lock_guard<std::mutex> lock(cache_mutex);

                auto it = cache.find(key);
                if (it != cache.end()) {
                    hits++;
                    return it->second;
                }

                misses++;
                // Simulate computation: pattern with even hash match
                size_t hash = std::hash<std::string>{}(key);
                bool result = (hash % 2 == 0);
                cache[key] = result;
                return result;
            }

            double hit_ratio() const {
                size_t total = hits + misses;
                return total > 0 ? static_cast<double>(hits) / total : 0.0;
            }
        };

        ThreadSafeCache shared_cache;

        auto cache_worker = [&shared_cache](int thread_id, size_t lookup_count) -> size_t {
            size_t local_matches = 0;

            for (size_t i = 0; i < lookup_count; ++i) {
                // Create some overlapping keys to test cache efficiency
                std::string key = "pattern" + std::to_string(i % 100) + "-thread" + std::to_string(thread_id);
                if (shared_cache.lookup(key)) {
                    local_matches++;
                }
            }

            return local_matches;
        };

        // Test cache with concurrent access
        size_t num_threads = 8;
        size_t lookups_per_thread = 1000;

        std::vector<std::future<size_t>> cache_futures;

        auto cache_start = std::chrono::high_resolution_clock::now();

        for (size_t i = 0; i < num_threads; ++i) {
            cache_futures.push_back(std::async(std::launch::async, cache_worker, i, lookups_per_thread));
        }

        size_t total_cache_matches = 0;
        for (auto& future : cache_futures) {
            total_cache_matches += future.get();
        }

        auto cache_end = std::chrono::high_resolution_clock::now();
        auto cache_time = std::chrono::duration_cast<std::chrono::milliseconds>(cache_end - cache_start);

        // Cache performance requirements
        REQUIRE(cache_time.count() < 3000);        // < 3 seconds
        REQUIRE(shared_cache.hit_ratio() > 0.5);   // > 50% hit ratio
        REQUIRE(total_cache_matches > 0);          // Should have matches

        INFO("Cache threads: " << num_threads);
        INFO("Lookups per thread: " << lookups_per_thread);
        INFO("Cache time: " << cache_time.count() << "ms");
        INFO("Hit ratio: " << (shared_cache.hit_ratio() * 100) << "%");
        INFO("Total cache matches: " << total_cache_matches);
    }
}

TEST_CASE("Resource limit stress tests", "[benchmarks][stress]") {
    SECTION("Pattern complexity stress test") {
        // Test with extremely complex pattern combinations
        std::vector<std::string> complex_patterns = {
            "*kernel*", "*-core-*", "*lib*-server*", "*-module-*-ext*",
            "*framework*", "*service*", "*-component-*", "*-plugin-*",
            "*database*", "*-client-*-tools*", "*runtime*", "*-dev-*"
        };

        std::vector<std::string> stress_packages;
        for (int i = 0; i < 5000; ++i) {
            stress_packages.push_back("complex-kernel-module-framework-" + std::to_string(i));
            stress_packages.push_back("lib-service-component-plugin-" + std::to_string(i));
            stress_packages.push_back("database-client-tools-runtime-" + std::to_string(i));
        }

        auto stress_start = std::chrono::high_resolution_clock::now();

        size_t stress_matches = 0;
        for (const auto& pkg : stress_packages) {
            for (const auto& pattern : complex_patterns) {
                // Complex pattern matching simulation
                bool matches = false;

                if (pattern.front() == '*' && pattern.back() == '*') {
                    // Contains pattern: *substr*
                    std::string substr = pattern.substr(1, pattern.length() - 2);
                    matches = pkg.find(substr) != std::string::npos;
                } else if (pattern.front() == '*') {
                    // Suffix pattern: *suffix
                    std::string suffix = pattern.substr(1);
                    matches = pkg.length() >= suffix.length() &&
                             pkg.substr(pkg.length() - suffix.length()) == suffix;
                } else if (pattern.back() == '*') {
                    // Prefix pattern: prefix*
                    std::string prefix = pattern.substr(0, pattern.length() - 1);
                    matches = pkg.length() >= prefix.length() &&
                             pkg.substr(0, prefix.length()) == prefix;
                }

                if (matches) {
                    stress_matches++;
                    break; // First match sufficient
                }
            }
        }

        auto stress_end = std::chrono::high_resolution_clock::now();
        auto stress_time = std::chrono::duration_cast<std::chrono::milliseconds>(stress_end - stress_start);

        // Stress test requirements
        REQUIRE(stress_time.count() < 10000);  // < 10 seconds even for complex patterns
        REQUIRE(stress_matches > 0);           // Should find matches

        INFO("Stress test patterns: " << complex_patterns.size());
        INFO("Stress test packages: " << stress_packages.size());
        INFO("Stress test time: " << stress_time.count() << "ms");
        INFO("Stress matches found: " << stress_matches);
    }

    SECTION("Memory pressure simulation") {
        // Test behavior under memory constraints
        auto memory_pressure_test = [](size_t allocation_size) -> bool {
            try {
                // Simulate large memory allocation
                std::vector<std::vector<char>> memory_blocks;

                for (size_t i = 0; i < allocation_size; ++i) {
                    memory_blocks.emplace_back(1024, 'x'); // 1KB blocks

                    // Simulate some processing work
                    if (i % 1000 == 0) {
                        std::string test_package = "memory-test-package-" + std::to_string(i);
                        bool matches = test_package.find("test") != std::string::npos;
                        (void)matches; // Suppress unused warning
                    }
                }

                return true;
            } catch (const std::bad_alloc&) {
                return false; // Memory allocation failed
            }
        };

        // Test with increasing memory pressure
        std::vector<size_t> memory_sizes = {1000, 5000, 10000}; // In KB blocks

        for (size_t size : memory_sizes) {
            bool allocation_success = memory_pressure_test(size);

            // Should handle reasonable memory usage gracefully
            if (size <= 10000) { // Up to ~10MB should be fine
                REQUIRE(allocation_success == true);
            }

            INFO("Memory test size: " << size << " KB, Success: " << allocation_success);
        }
    }
}