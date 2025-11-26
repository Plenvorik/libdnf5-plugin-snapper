// Copyright (C) 2025 Andre Herrlich <plenvorik@gmail.com>
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef LIBDNF5_PLUGIN_SNAPPER_HPP
#define LIBDNF5_PLUGIN_SNAPPER_HPP

#include <boost/regex.hpp>
#include <libdnf5/plugin/iplugin.hpp>
#include <snapper/Snapper.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

constexpr const char * PLUGIN_NAME = "snapper";
constexpr libdnf5::plugin::Version PLUGIN_VERSION{.major = 1, .minor = 0, .micro = 2};
constexpr libdnf5::PluginAPIVersion REQUIRED_PLUGIN_API_VERSION{.major = 2, .minor = 1};

constexpr const char * attrs[]{"author.name", "author.email", "description", nullptr};
constexpr const char * attrs_value[]{
    "Andre Herrlich", "plenvorik@gmail.com", "Creates snapper snapshots before and after DNF transactions"};


/**
 * @brief Package filter for wildcard and regex pattern matching
 *
 * Provides efficient filtering of package names using wildcards and regular expressions.
 * Features regex compilation caching for performance, automatic pattern validation,
 * and support for include/exclude/important pattern categories.
 *
 * Thread-safety: Const operations are thread-safe via mutable cache (logical constness).
 * Cache operations do not affect observable state but are not protected by mutex.
 *
 * @note Pattern syntax: Wildcards (* and ?) are converted to regex automatically
 * @note Precedence: Exclude patterns override include patterns
 */
class PackageFilter {
public:
    PackageFilter() = default;
    ~PackageFilter() = default;

    PackageFilter(const PackageFilter &) = delete;
    PackageFilter & operator=(const PackageFilter &) = delete;
    PackageFilter(PackageFilter &&) = default;
    PackageFilter & operator=(PackageFilter &&) = default;

    /**
     * @brief Set include patterns for package filtering
     *
     * @param patterns Vector of wildcard/regex patterns (e.g., "kernel-*", "glibc")
     *
     * Empty patterns mean include all packages (default behavior).
     * Patterns are validated and compiled to regex on first use.
     * Cache is cleared when patterns change.
     */
    void setIncludePatterns(const std::vector<std::string> & patterns);

    /**
     * @brief Set exclude patterns for package filtering
     *
     * @param patterns Vector of wildcard/regex patterns to exclude
     *
     * Exclude patterns always override include patterns.
     * Cache is cleared when patterns change.
     */
    void setExcludePatterns(const std::vector<std::string> & patterns);

    /**
     * @brief Set important package patterns for metadata marking
     *
     * @param patterns Vector of wildcard/regex patterns for critical packages
     *
     * Packages matching these patterns trigger "important" cleanup algorithm
     * and special metadata tagging in snapshots.
     */
    void setImportantPatterns(const std::vector<std::string> & patterns);

    /**
     * @brief Comprehensive package analysis result
     */
    struct PackageAnalysis {
        bool should_create_snapshot{false};
        bool matches_include{false};
        bool matches_exclude{false};
        bool is_important{false};
    };

    /**
     * @brief Perform comprehensive package analysis
     *
     * @param package_name Name of the package to analyze
     * @return PackageAnalysis struct with all analysis results
     *
     * This is the primary analysis method providing:
     * - Snapshot creation decision (considering include/exclude precedence)
     * - Include pattern matching status
     * - Exclude pattern matching status
     * - Important package status
     *
     * Performs single-pass analysis with cached regex compilation.
     */
    PackageAnalysis analyzePackage(const std::string & package_name) const;

    /**
     * @brief Filter statistics for monitoring and diagnostics
     */
    struct FilterStats {
        size_t include_patterns{0};
        size_t exclude_patterns{0};
        size_t important_patterns{0};
        size_t cached_regexes{0};
        size_t failed_patterns{0};
        size_t cache_hits{0};
        size_t cache_misses{0};
        bool has_wildcard_include{false};
    };

    /**
     * @brief Get current filter statistics
     *
     * @return FilterStats struct with current statistics
     *
     * Useful for diagnostics, logging, and performance monitoring.
     * Cache hit ratio can be calculated as: hits / (hits + misses)
     */
    FilterStats getStats() const;

private:
    /**
     * @brief Convert wildcard pattern to regex pattern
     *
     * @param pattern Wildcard pattern with * and ? characters
     * @return Anchored regex pattern string
     *
     * Conversions:
     * - * becomes .*
     * - ? becomes .
     * - Special regex chars are escaped
     * - Pattern is anchored with ^ and $
     */
    static std::string wildcardToRegex(const std::string & pattern);

    /**
     * @brief Get compiled regex for pattern (with caching)
     *
     * @param pattern Wildcard pattern to compile
     * @return Reference to compiled boost::regex
     *
     * Caches compiled regex to avoid recompilation overhead.
     * Returns empty regex (matches nothing) on compilation failure.
     * Failed patterns are tracked to prevent retry storms.
     *
     * Cache cleanup triggered automatically at 500 entries.
     */
    const boost::regex & getCompiledRegex(const std::string & pattern) const;

    /**
     * @brief Check if package name matches any pattern in list
     *
     * @param package_name Name to match
     * @param patterns List of patterns to check
     * @return true if any pattern matches
     *
     * Uses cached compiled regex for performance.
     * Falls back to exact string match on regex errors.
     */
    bool matchesAnyPattern(const std::string & package_name, const std::vector<std::string> & patterns) const;

    /**
     * @brief Validate and filter patterns
     *
     * @param patterns Input patterns to validate
     * @return Validated patterns with empty strings removed
     *
     * Currently filters out empty patterns.
     * Future: Could add additional security validation.
     */
    std::vector<std::string> validatePatterns(const std::vector<std::string> & patterns) const;

    /**
     * @brief Clean up regex cache and failed patterns
     *
     * Removes half of cached regex entries and failed pattern entries.
     * Called automatically when cache reaches size threshold.
     */
    void cleanupCache() const;

    /**
     * @brief Update wildcard detection flags
     *
     * Detects if include patterns contain wildcard-all patterns (* or ** or *.*).
     * Used for optimization: wildcard-all matches everything without regex.
     */
    void updateWildcardFlags();

    std::vector<std::string> include_patterns_;
    std::vector<std::string> exclude_patterns_;
    std::vector<std::string> important_patterns_;

    mutable std::unordered_map<std::string, boost::regex> regex_cache_;
    mutable std::unordered_set<std::string> failed_patterns_;
    mutable size_t cache_hits_{0};
    mutable size_t cache_misses_{0};

    bool has_wildcard_include_{false};
};

/**
 * @brief DNF5 plugin for automatic snapper snapshot creation
 *
 * Creates paired pre/post snapshots around DNF package transactions.
 * Integrates with snapper's native snapshot management and cleanup algorithms.
 *
 * Features:
 * - Automatic snapshot creation before/after transactions
 * - Package filtering (include/exclude patterns with wildcards)
 * - Important package detection for special cleanup handling
 * - Rich metadata collection (transaction details, user, caller program)
 * - Dryrun mode for testing
 * - Comprehensive error handling (never aborts transactions)
 *
 * Configuration file: /etc/dnf/libdnf5-plugins/snapper.conf
 *
 * @note Implements libdnf5::plugin::IPlugin2_1 API version 2.1
 */
class SnapperPlugin final : public libdnf5::plugin::IPlugin2_1 {
public:
    /**
     * @brief Construct plugin and load configuration
     *
     * @param data Plugin data interface from libdnf5
     * @param parser Configuration parser with loaded config file
     *
     * Constructor only loads configuration and stores it.
     * Actual initialization (logger access, snapper connection) happens in init().
     *
     * @note Configuration errors are stored and logged later in init()
     */
    SnapperPlugin(libdnf5::plugin::IPluginData & data, libdnf5::ConfigParser & parser);
    ~SnapperPlugin() override = default;

    /**
     * @brief Get required plugin API version
     * @return API version 2.1
     */
    libdnf5::PluginAPIVersion get_api_version() const noexcept override { return REQUIRED_PLUGIN_API_VERSION; }

    /**
     * @brief Get plugin name
     * @return "snapper"
     */
    const char * get_name() const noexcept override { return PLUGIN_NAME; }

    /**
     * @brief Get plugin version
     * @return Version 1.0.0
     */
    libdnf5::plugin::Version get_version() const noexcept override { return PLUGIN_VERSION; }

    /**
     * @brief Get plugin attributes
     * @return Array of attribute names
     */
    const char * const * get_attributes() const noexcept override { return attrs; }

    /**
     * @brief Get specific attribute value
     * @param attribute Attribute name to query
     * @return Attribute value or nullptr if not found
     */
    const char * get_attribute(const char * attribute) const noexcept override {
        for (size_t i = 0; attrs[i]; ++i) {
            if (std::strcmp(attribute, attrs[i]) == 0) {
                return attrs_value[i];
            }
        }
        return nullptr;
    }

    /**
     * @brief Initialize plugin and establish snapper connection
     *
     * Logs configuration, establishes snapper connection, validates access.
     * Reports any configuration errors stored during construction.
     *
     * On error: Disables snapper integration but does not throw.
     * Plugin remains loaded but becomes no-op for transactions.
     */
    void init() override;

    /**
     * @brief Clean up plugin resources
     *
     * Resets snapper connection and clears cached state.
     * Called during DNF5 shutdown.
     */
    void finish() noexcept override;

    /**
     * @brief Pre-transaction hook - create pre-snapshot
     *
     * @param transaction DNF transaction about to execute
     *
     * Analyzes transaction packages against filter criteria.
     * Creates pre-snapshot if any packages match include patterns.
     * Stores snapshot number for pairing in post_transaction().
     *
     * Stores FilterDecision for consistent metadata in post-snapshot.
     *
     * Error handling: Logs errors, continues transaction (never throws).
     */
    void pre_transaction(const libdnf5::base::Transaction & transaction) override;

    /**
     * @brief Post-transaction hook - create post-snapshot
     *
     * @param transaction DNF transaction that completed
     *
     * Creates post-snapshot paired with pre-snapshot from pre_transaction().
     * Uses stored FilterDecision for consistent metadata.
     * Marks transaction as successful in snapshot metadata.
     *
     * Error handling: Logs errors, continues (never throws).
     * Pre-snapshot remains unpaired if post-snapshot creation fails.
     */
    void post_transaction(const libdnf5::base::Transaction & transaction) override;

private:
    /**
     * @brief Plugin configuration structure
     */
    struct Config {
        bool enabled{true};
        bool dryrun{false};
        std::string snapper_config{"root"};
        std::string cleanup_algorithm{"number"};
        std::string root_prefix{"/"};
    };

    /**
     * @brief Load configuration from INI parser
     *
     * @param parser Configuration parser with /etc/dnf/libdnf5-plugins/snapper.conf
     *
     * Parses main section and filter section.
     * Validates values and stores error messages for later logging.
     * Falls back to defaults on errors.
     */
    void load_config(libdnf5::ConfigParser & parser);

    /**
     * @brief Generate human-readable snapshot description
     *
     * @param transaction DNF transaction reference
     * @param type "pre" or "post"
     * @return Formatted description string
     *
     * Format: "libdnf5(dnf5) transaction (pre)"
     * Includes caller program name for traceability.
     */
    std::string generateSnapshotDescription(const libdnf5::base::Transaction & transaction, const std::string & type);

    /**
     * @brief Collect transaction operation counts
     *
     * @param transaction DNF transaction to analyze
     * @return Map of operation type to count
     *
     * Counts: install, upgrade, remove, downgrade, reinstall, other
     * Used for compact metadata encoding in snapshots.
     */
    std::map<std::string, int> collectTransactionCounts(const libdnf5::base::Transaction & transaction) const;

    /**
     * @brief Detect caller program name
     *
     * @return Program name (e.g., "dnf5") or "unknown"
     *
     * Reads /proc/self/comm for reliable process name.
     * Sanitizes output (removes non-printable characters).
     */
    std::string getCallerProgram() const;

    /**
     * @brief Add transaction metadata to snapshot configuration
     *
     * @param scd Snapper configuration data to populate
     * @param transaction DNF transaction reference
     *
     * Adds compact metadata:
     * - ops: Transaction operations (e.g., "i2,r1,u3")
     * - sudo: SUDO_USER if different from current user
     *
     * Validates environment variables for security.
     */
    void addTransactionMetadata(snapper::SCD & scd, const libdnf5::base::Transaction & transaction) const;

    /**
     * @brief Load filter configuration from parser
     *
     * @param parser Configuration parser
     *
     * Parses filter section:
     * - include_packages: Comma-separated wildcard patterns
     * - exclude_packages: Comma-separated wildcard patterns
     * - important_packages: Comma-separated wildcard patterns
     *
     * Validates patterns and stores error messages.
     */
    void loadFilterConfig(libdnf5::ConfigParser & parser);

    /**
     * @brief Parse comma-separated pattern list
     *
     * @param pattern_string Comma-separated patterns
     * @return Vector of trimmed pattern strings
     *
     * Splits on commas, trims whitespace, skips empty entries.
     */
    std::vector<std::string> parsePatternList(const std::string & pattern_string) const;

    /**
     * @brief Filter decision result for transaction analysis
     */
    struct FilterDecision {
        bool should_create_snapshot{false};
        bool is_important_transaction{false};
        std::vector<std::string> matching_packages;
        std::vector<std::string> excluded_packages;
        std::vector<std::string> ignored_packages;
        std::vector<std::string> important_packages;
        size_t total_packages{0};
    };

    /**
     * @brief Analyze transaction packages for snapshot decision
     *
     * @param transaction DNF transaction to analyze
     * @return FilterDecision with complete analysis
     *
     * Performs single-pass analysis of all transaction packages.
     * Categorizes packages: matching, excluded, ignored, important.
     * Determines snapshot creation decision and importance.
     *
     * Used by both pre_transaction() and post_transaction() for consistent metadata.
     */
    FilterDecision analyzeTransactionForSnapshot(const libdnf5::base::Transaction & transaction) const;

    Config config_;
    std::unique_ptr<snapper::Snapper> snapper_;
    std::optional<unsigned int> pre_snapshot_num_;
    PackageFilter package_filter_;

    std::string config_error_message_;

    std::optional<FilterDecision> stored_filter_decision_;
};

}  // anonymous namespace

#endif  // LIBDNF5_PLUGIN_SNAPPER_HPP