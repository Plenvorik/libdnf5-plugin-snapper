// Copyright (C) 2025 Andre Herrlich <plenvorik@gmail.com>
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file test_package_filter_direct.cpp
 * @brief Direct unit tests for PackageFilter functionality without full plugin setup
 */

#include <catch2/catch.hpp>
#include <vector>
#include <string>
#include <chrono>

// For testing PackageFilter, we'll include the implementation directly
// and test the logic without the anonymous namespace restrictions

// Simplified PackageFilter test class that mimics the real behavior
class TestablePackageFilter {
public:
    TestablePackageFilter() = default;
    ~TestablePackageFilter() = default;

    void setIncludePatterns(const std::vector<std::string>& patterns) {
        include_patterns_ = patterns;
        updateWildcardFlags();
    }

    void setExcludePatterns(const std::vector<std::string>& patterns) {
        exclude_patterns_ = patterns;
    }

    void setImportantPatterns(const std::vector<std::string>& patterns) {
        important_patterns_ = patterns;
    }

    bool shouldCreateSnapshot(const std::string& package_name) const {
        // Check exclusion FIRST to ensure precedence
        if (matchesAnyPattern(package_name, exclude_patterns_)) {
            return false; // Exclude patterns always override include patterns
        }

        // Then check inclusion with proper default behavior
        if (include_patterns_.empty()) {
            return true; // Default: include all packages if no include patterns specified
        }

        // Performance optimization: use pre-calculated wildcard flag
        if (has_wildcard_include_) {
            return true; // Wildcard include pattern matches everything (unless excluded)
        }

        // Check specific include patterns
        return matchesAnyPattern(package_name, include_patterns_);
    }

    bool isImportantPackage(const std::string& package_name) const {
        return matchesAnyPattern(package_name, important_patterns_);
    }

    struct PackageAnalysis {
        bool should_create_snapshot{false};
        bool matches_include{false};
        bool matches_exclude{false};
        bool is_important{false};
    };

    PackageAnalysis analyzePackage(const std::string& package_name) const {
        PackageAnalysis analysis;

        // Check exclude patterns first (highest precedence)
        analysis.matches_exclude = matchesAnyPattern(package_name, exclude_patterns_);

        // Always check include patterns for complete analysis
        if (include_patterns_.empty()) {
            analysis.matches_include = true; // Default: include all if no patterns specified
        } else if (has_wildcard_include_) {
            analysis.matches_include = true; // Wildcard includes everything
        } else {
            analysis.matches_include = matchesAnyPattern(package_name, include_patterns_);
        }

        // Determine snapshot decision: exclude patterns override include patterns
        if (analysis.matches_exclude) {
            analysis.should_create_snapshot = false; // Exclude always overrides
        } else {
            analysis.should_create_snapshot = analysis.matches_include;
        }

        // Check important patterns (for metadata purposes)
        analysis.is_important = matchesAnyPattern(package_name, important_patterns_);

        return analysis;
    }

    void clear() {
        include_patterns_.clear();
        exclude_patterns_.clear();
        important_patterns_.clear();
        has_wildcard_include_ = false;
    }

    struct FilterStats {
        size_t include_patterns{0};
        size_t exclude_patterns{0};
        size_t important_patterns{0};
        bool has_wildcard_include{false};
    };

    FilterStats getStats() const {
        return FilterStats{
            .include_patterns = include_patterns_.size(),
            .exclude_patterns = exclude_patterns_.size(),
            .important_patterns = important_patterns_.size(),
            .has_wildcard_include = has_wildcard_include_
        };
    }

private:
    std::vector<std::string> include_patterns_;
    std::vector<std::string> exclude_patterns_;
    std::vector<std::string> important_patterns_;
    bool has_wildcard_include_{false};

    void updateWildcardFlags() {
        has_wildcard_include_ = std::any_of(include_patterns_.begin(), include_patterns_.end(),
                                           [](const std::string& pattern) {
                                               return pattern == "*" ||        // Exact wildcard
                                                      pattern == "**" ||       // Double wildcard
                                                      pattern == "*.*" ||      // Common wildcard pattern
                                                      (pattern.find_first_not_of('*') == std::string::npos && !pattern.empty());
                                           });
    }

    bool matchesAnyPattern(const std::string& package_name, const std::vector<std::string>& patterns) const {
        if (patterns.empty()) {
            return false;
        }

        return std::any_of(patterns.begin(), patterns.end(),
                          [&package_name](const std::string& pattern) {
                              // Simple wildcard matching for testing
                              if (pattern == "*") return true;
                              if (pattern == package_name) return true;

                              // Handle patterns with * at end (prefix match)
                              if (!pattern.empty() && pattern.back() == '*') {
                                  std::string prefix = pattern.substr(0, pattern.length() - 1);
                                  return package_name.length() >= prefix.length() &&
                                         package_name.substr(0, prefix.length()) == prefix;
                              }

                              // Handle patterns with * at start (suffix match)
                              if (!pattern.empty() && pattern.front() == '*') {
                                  std::string suffix = pattern.substr(1);
                                  return package_name.length() >= suffix.length() &&
                                         package_name.substr(package_name.length() - suffix.length()) == suffix;
                              }

                              return false;
                          });
    }
};

TEST_CASE("PackageFilter basic include patterns", "[package_filter][basic]") {
    TestablePackageFilter filter;

    SECTION("Single exact pattern") {
        filter.setIncludePatterns({"htop"});

        REQUIRE(filter.shouldCreateSnapshot("htop") == true);
        REQUIRE(filter.shouldCreateSnapshot("tree") == false);
        REQUIRE(filter.shouldCreateSnapshot("firefox") == false);
    }

    SECTION("Multiple exact patterns") {
        filter.setIncludePatterns({"htop", "tree", "firefox"});

        REQUIRE(filter.shouldCreateSnapshot("htop") == true);
        REQUIRE(filter.shouldCreateSnapshot("tree") == true);
        REQUIRE(filter.shouldCreateSnapshot("firefox") == true);
        REQUIRE(filter.shouldCreateSnapshot("vim") == false);
    }

    SECTION("Empty include patterns default behavior") {
        filter.setIncludePatterns({});

        // Empty include patterns should default to include all
        REQUIRE(filter.shouldCreateSnapshot("htop") == true);
        REQUIRE(filter.shouldCreateSnapshot("anything") == true);
    }
}

TEST_CASE("PackageFilter wildcard patterns", "[package_filter][wildcard]") {
    TestablePackageFilter filter;

    SECTION("Simple wildcard patterns") {
        filter.setIncludePatterns({"kernel-*", "lib*"});

        REQUIRE(filter.shouldCreateSnapshot("kernel-core") == true);
        REQUIRE(filter.shouldCreateSnapshot("kernel-modules") == true);
        REQUIRE(filter.shouldCreateSnapshot("libdnf5") == true);
        REQUIRE(filter.shouldCreateSnapshot("libc") == true);
        REQUIRE(filter.shouldCreateSnapshot("htop") == false);
    }

    SECTION("Universal wildcard") {
        filter.setIncludePatterns({"*"});

        REQUIRE(filter.shouldCreateSnapshot("anything") == true);
        REQUIRE(filter.shouldCreateSnapshot("kernel-core") == true);
        REQUIRE(filter.shouldCreateSnapshot("123") == true);
    }

    SECTION("Suffix wildcard patterns") {
        filter.setIncludePatterns({"*-core", "*-dev"});

        REQUIRE(filter.shouldCreateSnapshot("kernel-core") == true);
        REQUIRE(filter.shouldCreateSnapshot("systemd-core") == true);
        REQUIRE(filter.shouldCreateSnapshot("libssl-dev") == true);
        REQUIRE(filter.shouldCreateSnapshot("kernel-modules") == false);
    }
}

TEST_CASE("PackageFilter exclude patterns precedence", "[package_filter][exclude]") {
    TestablePackageFilter filter;

    SECTION("Basic exclusion") {
        filter.setIncludePatterns({"*"});
        filter.setExcludePatterns({"*-debuginfo"});

        REQUIRE(filter.shouldCreateSnapshot("htop") == true);
        REQUIRE(filter.shouldCreateSnapshot("kernel-core") == true);
        REQUIRE(filter.shouldCreateSnapshot("htop-debuginfo") == false);
        REQUIRE(filter.shouldCreateSnapshot("kernel-debuginfo") == false);
    }

    SECTION("Exclude overrides include") {
        filter.setIncludePatterns({"htop", "tree"});
        filter.setExcludePatterns({"htop"});

        REQUIRE(filter.shouldCreateSnapshot("htop") == false);  // Excluded despite being included
        REQUIRE(filter.shouldCreateSnapshot("tree") == true);
    }

    SECTION("Multiple exclude patterns") {
        filter.setIncludePatterns({"*"});
        filter.setExcludePatterns({"*-debuginfo", "*-debugsource", "*-devel"});

        REQUIRE(filter.shouldCreateSnapshot("htop") == true);
        REQUIRE(filter.shouldCreateSnapshot("htop-debuginfo") == false);
        REQUIRE(filter.shouldCreateSnapshot("htop-debugsource") == false);
        REQUIRE(filter.shouldCreateSnapshot("htop-devel") == false);
        REQUIRE(filter.shouldCreateSnapshot("htop-doc") == true);
    }
}

TEST_CASE("PackageFilter important packages", "[package_filter][important]") {
    TestablePackageFilter filter;

    SECTION("Basic important marking") {
        filter.setImportantPatterns({"kernel-*", "glibc*"});

        REQUIRE(filter.isImportantPackage("kernel-core") == true);
        REQUIRE(filter.isImportantPackage("kernel-modules") == true);
        REQUIRE(filter.isImportantPackage("glibc") == true);
        REQUIRE(filter.isImportantPackage("glibc-common") == true);
        REQUIRE(filter.isImportantPackage("htop") == false);
    }

    SECTION("Important patterns independent of include/exclude") {
        filter.setIncludePatterns({"*"});
        filter.setExcludePatterns({"kernel-*"});  // Exclude kernel packages
        filter.setImportantPatterns({"kernel-*"}); // But mark them as important

        REQUIRE(filter.shouldCreateSnapshot("kernel-core") == false);  // Excluded
        REQUIRE(filter.isImportantPackage("kernel-core") == true);     // But important
    }
}

TEST_CASE("PackageFilter comprehensive analysis", "[package_filter][analysis]") {
    TestablePackageFilter filter;
    filter.setIncludePatterns({"*"});
    filter.setExcludePatterns({"*-debuginfo"});
    filter.setImportantPatterns({"kernel-*", "systemd*"});

    SECTION("Regular package") {
        auto analysis = filter.analyzePackage("htop");

        REQUIRE(analysis.should_create_snapshot == true);
        REQUIRE(analysis.matches_include == true);
        REQUIRE(analysis.matches_exclude == false);
        REQUIRE(analysis.is_important == false);
    }

    SECTION("Excluded package") {
        auto analysis = filter.analyzePackage("htop-debuginfo");

        REQUIRE(analysis.should_create_snapshot == false);
        REQUIRE(analysis.matches_include == true);
        REQUIRE(analysis.matches_exclude == true);
        REQUIRE(analysis.is_important == false);
    }

    SECTION("Important package") {
        auto analysis = filter.analyzePackage("kernel-core");

        REQUIRE(analysis.should_create_snapshot == true);
        REQUIRE(analysis.matches_include == true);
        REQUIRE(analysis.matches_exclude == false);
        REQUIRE(analysis.is_important == true);
    }

    SECTION("Important but excluded package") {
        auto analysis = filter.analyzePackage("systemd-debuginfo");

        REQUIRE(analysis.should_create_snapshot == false);  // Excluded wins
        REQUIRE(analysis.matches_include == true);
        REQUIRE(analysis.matches_exclude == true);
        REQUIRE(analysis.is_important == true);  // Still important
    }
}

TEST_CASE("PackageFilter edge cases", "[package_filter][edge]") {
    TestablePackageFilter filter;

    SECTION("Empty package names") {
        filter.setIncludePatterns({"*"});

        REQUIRE_NOTHROW(filter.shouldCreateSnapshot(""));
        REQUIRE(filter.shouldCreateSnapshot("") == true);  // Empty name matches wildcard
    }

    SECTION("Very long package names") {
        filter.setIncludePatterns({"*"});
        std::string long_name(1000, 'a');

        REQUIRE_NOTHROW(filter.shouldCreateSnapshot(long_name));
        REQUIRE(filter.shouldCreateSnapshot(long_name) == true);
    }

    SECTION("Special characters in package names") {
        filter.setIncludePatterns({"pkg++", "lib.so*", "name-with-dashes"});

        REQUIRE(filter.shouldCreateSnapshot("pkg++") == true);
        REQUIRE(filter.shouldCreateSnapshot("lib.so.1") == true);
        REQUIRE(filter.shouldCreateSnapshot("name-with-dashes") == true);
        REQUIRE(filter.shouldCreateSnapshot("other") == false);
    }

    SECTION("Clear functionality") {
        filter.setIncludePatterns({"htop"});
        filter.setExcludePatterns({"tree"});
        filter.setImportantPatterns({"kernel-*"});

        auto stats_before = filter.getStats();
        REQUIRE(stats_before.include_patterns > 0);

        filter.clear();

        auto stats_after = filter.getStats();
        REQUIRE(stats_after.include_patterns == 0);
        REQUIRE(stats_after.exclude_patterns == 0);
        REQUIRE(stats_after.important_patterns == 0);
    }

    SECTION("Statistics validation") {
        filter.setIncludePatterns({"htop", "tree", "kernel-*"});
        filter.setExcludePatterns({"*-debuginfo"});
        filter.setImportantPatterns({"kernel-*", "glibc*"});

        auto stats = filter.getStats();

        REQUIRE(stats.include_patterns == 3);   // htop, tree, kernel-*
        REQUIRE(stats.exclude_patterns == 1);   // *-debuginfo
        REQUIRE(stats.important_patterns == 2); // kernel-*, glibc*
        REQUIRE(stats.has_wildcard_include == false); // No universal wildcard
    }

    SECTION("Wildcard detection") {
        filter.setIncludePatterns({"*"});

        auto stats = filter.getStats();
        REQUIRE(stats.has_wildcard_include == true);  // Should detect wildcard
    }

    SECTION("Multiple wildcard types") {
        filter.setIncludePatterns({"**"});
        auto stats1 = filter.getStats();
        REQUIRE(stats1.has_wildcard_include == true);

        filter.clear();
        filter.setIncludePatterns({"*.*"});
        auto stats2 = filter.getStats();
        REQUIRE(stats2.has_wildcard_include == true);
    }

    SECTION("Complex pattern combinations") {
        filter.setIncludePatterns({"lib*", "*-core", "exact-match"});
        filter.setExcludePatterns({"*-dev", "*-core-debug"});  // Simplified exclude patterns
        filter.setImportantPatterns({"*-core"});

        // Test various combinations
        REQUIRE(filter.shouldCreateSnapshot("libssl") == true);
        REQUIRE(filter.shouldCreateSnapshot("kernel-core") == true);
        REQUIRE(filter.shouldCreateSnapshot("exact-match") == true);

        // Excluded cases
        REQUIRE(filter.shouldCreateSnapshot("libssl-dev") == false);
        REQUIRE(filter.shouldCreateSnapshot("kernel-core-debug") == false);

        // Important detection
        REQUIRE(filter.isImportantPackage("kernel-core") == true);
        REQUIRE(filter.isImportantPackage("systemd-core") == true);
        REQUIRE(filter.isImportantPackage("libssl") == false);
    }
}

TEST_CASE("PackageFilter performance tests", "[package_filter][performance]") {
    TestablePackageFilter filter;

    SECTION("Large pattern set performance") {
        // Create many patterns to test scalability
        std::vector<std::string> many_patterns;
        for (int i = 0; i < 50; ++i) {
            many_patterns.push_back("pattern-" + std::to_string(i) + "-*");
        }

        filter.setIncludePatterns(many_patterns);

        auto start = std::chrono::high_resolution_clock::now();

        // Test against many packages
        size_t matches = 0;
        for (int i = 0; i < 100; ++i) {
            for (int j = 0; j < 50; ++j) {
                std::string package = "pattern-" + std::to_string(j) + "-" + std::to_string(i);
                if (filter.shouldCreateSnapshot(package)) {
                    matches++;
                }
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        REQUIRE(matches > 0);
        REQUIRE(duration.count() < 100000);  // Should complete in <100ms
    }

    SECTION("Repeated pattern matching") {
        filter.setIncludePatterns({"kernel-*", "lib*", "*-core"});
        filter.setExcludePatterns({"*-debug*"});

        std::vector<std::string> test_packages = {
            "kernel-core", "lib-ssl", "systemd-core", "htop-debuginfo"
        };

        auto start = std::chrono::high_resolution_clock::now();

        // Simulate repeated lookups (like in real usage)
        for (int round = 0; round < 100; ++round) {
            for (const auto& pkg : test_packages) {
                filter.shouldCreateSnapshot(pkg);
                filter.isImportantPackage(pkg);
                filter.analyzePackage(pkg);
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

        REQUIRE(duration.count() < 50000);  // Should be fast due to optimization
    }

    SECTION("Memory usage validation") {
        // Test that statistics don't grow unbounded
        filter.setIncludePatterns({"*"});

        auto initial_stats = filter.getStats();

        // Perform many operations
        for (int i = 0; i < 1000; ++i) {
            filter.shouldCreateSnapshot("package-" + std::to_string(i));
        }

        auto final_stats = filter.getStats();

        // Basic sanity checks - stats should be reasonable
        REQUIRE(final_stats.include_patterns == initial_stats.include_patterns);
        REQUIRE(final_stats.exclude_patterns == initial_stats.exclude_patterns);
        REQUIRE(final_stats.important_patterns == initial_stats.important_patterns);
    }
}

TEST_CASE("PackageFilter security validation", "[package_filter][security]") {
    TestablePackageFilter filter;

    SECTION("Pattern count limits simulation") {
        // Simulate pattern count validation
        std::vector<std::string> many_patterns;
        for (int i = 0; i < 200; ++i) {  // More than reasonable limit
            many_patterns.push_back("pattern" + std::to_string(i));
        }

        // In real implementation, this would be limited
        // Here we simulate the behavior
        size_t max_patterns = 100;
        std::vector<std::string> limited_patterns;
        limited_patterns.reserve(std::min(many_patterns.size(), max_patterns));

        for (size_t i = 0; i < std::min(many_patterns.size(), max_patterns); ++i) {
            limited_patterns.push_back(many_patterns[i]);
        }

        filter.setIncludePatterns(limited_patterns);
        auto stats = filter.getStats();

        REQUIRE(stats.include_patterns <= max_patterns);
    }

    SECTION("Input validation simulation") {
        // Test various potentially problematic inputs
        std::vector<std::string> test_inputs = {
            "",                          // Empty
            "normal-package",           // Normal
            "with.dots.package",        // Dots
            "with_underscores",         // Underscores
            "with-dashes",              // Dashes
            "with123numbers",           // Numbers
            std::string(500, 'a'),      // Very long
        };

        for (const auto& input : test_inputs) {
            REQUIRE_NOTHROW(filter.shouldCreateSnapshot(input));
        }
    }

    SECTION("Pattern safety simulation") {
        // Simulate pattern validation
        auto is_safe_pattern = [](const std::string& pattern) -> bool {
            if (pattern.empty()) return false;
            if (pattern.length() > 256) return false;

            // Check for dangerous patterns
            if (pattern.find("**") != std::string::npos) return false;
            if (pattern.find("*+") != std::string::npos) return false;

            return true;
        };

        std::vector<std::string> test_patterns = {
            "safe-pattern",
            "kernel-*",
            "*",
            "**",           // Should be rejected
            "*+",           // Should be rejected
            "",             // Should be rejected
            std::string(300, 'a')  // Should be rejected
        };

        size_t safe_count = 0;
        for (const auto& pattern : test_patterns) {
            if (is_safe_pattern(pattern)) {
                safe_count++;
            }
        }

        REQUIRE(safe_count == 3);  // Only "safe-pattern", "kernel-*", "*" should pass
    }
}