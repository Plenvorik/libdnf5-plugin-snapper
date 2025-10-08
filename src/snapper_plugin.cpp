// Copyright (C) 2025 Andre Herrlich <plenvorik@gmail.com>
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "snapper_plugin.hpp"

#include <boost/regex.hpp>
#include <fmt/format.h>
#include <libdnf5/base/base.hpp>
#include <libdnf5/base/transaction.hpp>
#include <libdnf5/conf/config_parser.hpp>
#include <libdnf5/logger/logger.hpp>
#include <libdnf5/transaction/transaction_item_action.hpp>
#include <snapper/Exception.h>
#include <snapper/Plugins.h>
#include <snapper/Snapper.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <functional>
#include <iostream>
#include <set>
#include <sstream>

namespace {

std::exception_ptr last_exception;


void PackageFilter::setIncludePatterns(const std::vector<std::string> & patterns) {
    include_patterns_ = validatePatterns(patterns);
    updateWildcardFlags();

    regex_cache_.clear();
    failed_patterns_.clear();
    cache_hits_ = 0;
    cache_misses_ = 0;
}

void PackageFilter::setExcludePatterns(const std::vector<std::string> & patterns) {
    exclude_patterns_ = validatePatterns(patterns);

    regex_cache_.clear();
    failed_patterns_.clear();
    cache_hits_ = 0;
    cache_misses_ = 0;
}

void PackageFilter::setImportantPatterns(const std::vector<std::string> & patterns) {
    important_patterns_ = validatePatterns(patterns);

    regex_cache_.clear();
    failed_patterns_.clear();
    cache_hits_ = 0;
    cache_misses_ = 0;
}

PackageFilter::FilterStats PackageFilter::getStats() const {
    return FilterStats{
        .include_patterns = include_patterns_.size(),
        .exclude_patterns = exclude_patterns_.size(),
        .important_patterns = important_patterns_.size(),
        .cached_regexes = regex_cache_.size(),
        .failed_patterns = failed_patterns_.size(),
        .cache_hits = cache_hits_,
        .cache_misses = cache_misses_,
        .has_wildcard_include = has_wildcard_include_};
}

std::string PackageFilter::wildcardToRegex(const std::string & pattern) {
    std::string regex_pattern;
    regex_pattern.reserve(pattern.size() * 2);

    regex_pattern += '^';

    for (char c : pattern) {
        switch (c) {
            case '*':
                regex_pattern += ".*";
                break;
            case '?':
                regex_pattern += '.';
                break;
            case '.':
            case '+':
            case '(':
            case ')':
            case '[':
            case ']':
            case '{':
            case '}':
            case '^':
            case '$':
            case '|':
            case '\\':
                regex_pattern += '\\';
                regex_pattern += c;
                break;
            default:
                regex_pattern += c;
                break;
        }
    }

    regex_pattern += '$';

    return regex_pattern;
}

const boost::regex & PackageFilter::getCompiledRegex(const std::string & pattern) const {
    {
        auto it = regex_cache_.find(pattern);
        if (it != regex_cache_.end()) {
            cache_hits_++;
            return it->second;
        }

        if (failed_patterns_.count(pattern)) {
            cache_hits_++;
            static const boost::regex empty_regex("(?!)");
            return empty_regex;
        }
        cache_misses_++;
    }

    std::string regex_pattern = wildcardToRegex(pattern);

    try {
        boost::regex compiled_regex(regex_pattern, boost::regex::icase | boost::regex::optimize);

        if (regex_cache_.size() >= 500) {
            cleanupCache();
        }

        auto [inserted_it, success] = regex_cache_.emplace(pattern, std::move(compiled_regex));
        return inserted_it->second;
    } catch (const boost::regex_error & ex) {
        failed_patterns_.insert(pattern);
        static const boost::regex empty_regex("(?!)");
        return empty_regex;
    }
}


std::vector<std::string> PackageFilter::validatePatterns(const std::vector<std::string> & patterns) const {
    std::vector<std::string> validated_patterns;
    validated_patterns.reserve(patterns.size());

    for (const auto & pattern : patterns) {
        if (!pattern.empty()) {
            validated_patterns.push_back(pattern);
        }
    }

    return validated_patterns;
}

void PackageFilter::cleanupCache() const {
    if (regex_cache_.size() > 500) {
        auto cleanup_count = regex_cache_.size() / 2;
        auto it = regex_cache_.begin();
        for (size_t i = 0; i < cleanup_count && it != regex_cache_.end(); ++i) {
            it = regex_cache_.erase(it);
        }
    }

    if (failed_patterns_.size() > 100) {
        auto failed_it = failed_patterns_.begin();
        auto failed_cleanup_count = failed_patterns_.size() / 2;
        for (size_t i = 0; i < failed_cleanup_count && failed_it != failed_patterns_.end(); ++i) {
            failed_it = failed_patterns_.erase(failed_it);
        }
    }
}

void PackageFilter::updateWildcardFlags() {
    has_wildcard_include_ =
        std::any_of(include_patterns_.begin(), include_patterns_.end(), [](const std::string & pattern) {
            return pattern == "*" || pattern == "**" || pattern == "*.*" ||
                   (pattern.find_first_not_of('*') == std::string::npos && !pattern.empty());
        });
}

bool PackageFilter::matchesAnyPattern(
    const std::string & package_name, const std::vector<std::string> & patterns) const {
    if (patterns.empty()) {
        return false;
    }

    return std::any_of(patterns.begin(), patterns.end(), [this, &package_name](const std::string & pattern) {
        try {
            const auto & regex = getCompiledRegex(pattern);
            return boost::regex_match(package_name, regex);
        } catch (const boost::regex_error &) {
            return package_name == pattern;
        } catch (...) {
            return false;
        }
    });
}

PackageFilter::PackageAnalysis PackageFilter::analyzePackage(const std::string & package_name) const {
    PackageAnalysis analysis;

    analysis.matches_exclude = matchesAnyPattern(package_name, exclude_patterns_);

    if (include_patterns_.empty()) {
        analysis.matches_include = true;
    } else if (has_wildcard_include_) {
        analysis.matches_include = true;
    } else {
        analysis.matches_include = matchesAnyPattern(package_name, include_patterns_);
    }

    if (analysis.matches_exclude) {
        analysis.should_create_snapshot = false;
    } else {
        analysis.should_create_snapshot = analysis.matches_include;
    }

    analysis.is_important = matchesAnyPattern(package_name, important_patterns_);

    return analysis;
}

SnapperPlugin::SnapperPlugin(libdnf5::plugin::IPluginData & data, libdnf5::ConfigParser & parser) : IPlugin2_1(data) {
    load_config(parser);
}

void SnapperPlugin::init() {
    auto & logger = *get_base().get_logger();

    if (!config_error_message_.empty()) {
        logger.warning("SnapperPlugin configuration error: {} - using default values", config_error_message_);
    }

    if (!config_.enabled) {
        logger.info("SnapperPlugin::init() - plugin is disabled in configuration");
        return;
    }
    logger.debug("SnapperPlugin configuration loaded:");
    logger.debug("  enabled: {}", config_.enabled ? "true" : "false");
    logger.debug("  dryrun: {}", config_.dryrun ? "true" : "false");
    logger.debug("  snapper_config: {}", config_.snapper_config);
    logger.debug("  cleanup_algorithm: {}", config_.cleanup_algorithm);
    logger.debug("  root_prefix: {}", config_.root_prefix);

    auto filter_stats = package_filter_.getStats();
    logger.debug("SnapperPlugin filter configuration:");
    logger.debug(
        "  include_patterns: {} (wildcard_include: {})",
        filter_stats.include_patterns,
        filter_stats.has_wildcard_include);
    logger.debug("  exclude_patterns: {}", filter_stats.exclude_patterns);
    logger.debug("  important_patterns: {}", filter_stats.important_patterns);
    logger.debug(
        "  Security: failed_patterns: {}, cache_size: {}", filter_stats.failed_patterns, filter_stats.cached_regexes);

    if (config_.enabled) {
        try {
            logger.info("SnapperPlugin: Attempting to connect to snapper config '{}'", config_.snapper_config);

            snapper_ = std::make_unique<snapper::Snapper>(config_.snapper_config, config_.root_prefix);

            logger.debug("SnapperPlugin: Testing snapper connection with getConfigInfo()");
            const auto & config_info = snapper_->getConfigInfo();
            logger.info("SnapperPlugin: Successfully connected to snapper, subvolume: {}", config_info.get_subvolume());

            logger.debug("SnapperPlugin: Testing snapper connection with getSnapshots()");
            const auto & snapshots = snapper_->getSnapshots();
            logger.info(
                "SnapperPlugin: Found {} existing snapshots in config '{}'", snapshots.size(), config_.snapper_config);

            logger.info("SnapperPlugin: Snapper connection established successfully");

        } catch (const std::exception & ex) {
            logger.error(
                "SnapperPlugin: Failed to connect to snapper config '{}': {}", config_.snapper_config, ex.what());
            logger.error("SnapperPlugin: Snapper integration disabled due to connection failure");
            snapper_.reset();
        } catch (...) {
            logger.error(
                "SnapperPlugin: Unknown error occurred while connecting to snapper config '{}'",
                config_.snapper_config);
            logger.error("SnapperPlugin: Snapper integration disabled due to unknown error");
            snapper_.reset();
        }
    } else {
        logger.debug("SnapperPlugin: Snapper integration disabled by configuration");
    }
}

void SnapperPlugin::finish() noexcept {
    try {
        pre_snapshot_num_.reset();
        stored_filter_decision_.reset();
        snapper_.reset();
    } catch (...) {
    }
}

void SnapperPlugin::pre_transaction(const libdnf5::base::Transaction & transaction) {
    if (!config_.enabled) {
        return;
    }

    try {
        auto & logger = *get_base().get_logger();

        if (!snapper_) {
            logger.debug("SnapperPlugin::pre_transaction() - snapper connection not available, skipping");
            return;
        }

        const auto & packages = transaction.get_transaction_packages();
        logger.debug("SnapperPlugin::pre_transaction() - transaction has {} package operations", packages.size());

        auto filter_decision = analyzeTransactionForSnapshot(transaction);

        stored_filter_decision_ = filter_decision;

        auto filter_stats = package_filter_.getStats();
        logger.debug(
            "SnapperPlugin::pre_transaction() - Filter configuration: include:{} exclude:{} important:{}",
            filter_stats.include_patterns,
            filter_stats.exclude_patterns,
            filter_stats.important_patterns);
        logger.debug(
            "SnapperPlugin::pre_transaction() - Filter analysis: total:{} matching:{} excluded:{} ignored:{} "
            "important:{}",
            filter_decision.total_packages,
            filter_decision.matching_packages.size(),
            filter_decision.excluded_packages.size(),
            filter_decision.ignored_packages.size(),
            filter_decision.important_packages.size());

        if (filter_decision.is_important_transaction) {
            logger.info(
                "SnapperPlugin::pre_transaction() - Important transaction detected with {} important packages",
                filter_decision.important_packages.size());
        }
        if (!filter_decision.excluded_packages.empty()) {
            std::string package_list;
            for (size_t i = 0; i < filter_decision.excluded_packages.size(); ++i) {
                if (i > 0)
                    package_list += ", ";
                package_list += filter_decision.excluded_packages[i];
            }
            logger.debug("SnapperPlugin::pre_transaction() - Excluded packages: {}", package_list);
        }
        if (!filter_decision.ignored_packages.empty()) {
            std::string package_list;
            for (size_t i = 0; i < filter_decision.ignored_packages.size(); ++i) {
                if (i > 0)
                    package_list += ", ";
                package_list += filter_decision.ignored_packages[i];
            }
            logger.debug("SnapperPlugin::pre_transaction() - Ignored packages: {}", package_list);
        }
        if (!filter_decision.important_packages.empty()) {
            std::string package_list;
            for (size_t i = 0; i < filter_decision.important_packages.size(); ++i) {
                if (i > 0)
                    package_list += ", ";
                package_list += filter_decision.important_packages[i];
            }
            logger.info("SnapperPlugin::pre_transaction() - Important packages in transaction: {}", package_list);
        }

        if (!filter_decision.should_create_snapshot) {
            logger.info("SnapperPlugin: Skipping snapshot - no packages match filter criteria");
            return;
        }

        logger.info(
            "SnapperPlugin: Creating snapshot - {} package{} match filter criteria",
            filter_decision.matching_packages.size(),
            filter_decision.matching_packages.size() == 1 ? "" : "s");

        std::string description = generateSnapshotDescription(transaction, "pre");
        logger.debug("SnapperPlugin::pre_transaction() - snapshot description: {}", description);

        snapper::SCD scd;
        scd.description = description;

        if (filter_decision.is_important_transaction) {
            scd.cleanup = "important";
            logger.info(
                "SnapperPlugin::pre_transaction() - using 'important' cleanup algorithm for important transaction");
        } else {
            scd.cleanup = config_.cleanup_algorithm;
        }

        scd.uid = 0;

        addTransactionMetadata(scd, transaction);

        if (filter_decision.is_important_transaction && !filter_decision.important_packages.empty()) {
            std::string imp_packages;
            for (size_t i = 0; i < filter_decision.important_packages.size(); ++i) {
                if (i > 0)
                    imp_packages += ",";
                imp_packages += filter_decision.important_packages[i];
            }
            scd.userdata["imp"] = imp_packages;
        }

        if (config_.dryrun) {
            pre_snapshot_num_ = 99999;
            return;
        }

        logger.debug("SnapperPlugin::pre_transaction() - calling snapper->createPreSnapshot()");
        snapper::Plugins::Report report;
        auto snapshot_iter = snapper_->createPreSnapshot(scd, report);

        unsigned int snapshot_num = snapshot_iter->getNum();
        pre_snapshot_num_ = snapshot_num;

        logger.info("SnapperPlugin::pre_transaction() - created pre-transaction snapshot #{}", snapshot_num);
        logger.debug(
            "SnapperPlugin::pre_transaction() - snapshot #{} created successfully with description: {}",
            snapshot_num,
            description);

        if (!report.entries.empty()) {
            logger.debug(
                "SnapperPlugin::pre_transaction() - snapshot creation report has {} entries", report.entries.size());
            for (const auto & entry : report.entries) {
                logger.debug("SnapperPlugin::pre_transaction() - report: {} (exit: {})", entry.name, entry.exit_status);
            }
        }

    } catch (const snapper::Exception & ex) {
        auto & logger = *get_base().get_logger();
        logger.error("SnapperPlugin::pre_transaction() snapper error: {}", ex.what());
        logger.error("SnapperPlugin::pre_transaction() - continuing transaction without snapshot");
        pre_snapshot_num_.reset();
        stored_filter_decision_.reset();
    } catch (const std::exception & ex) {
        auto & logger = *get_base().get_logger();
        logger.error("SnapperPlugin::pre_transaction() error: {}", ex.what());
        logger.error("SnapperPlugin::pre_transaction() - continuing transaction without snapshot");
        pre_snapshot_num_.reset();
        stored_filter_decision_.reset();
    }
}

void SnapperPlugin::post_transaction(const libdnf5::base::Transaction & transaction) {
    if (!config_.enabled) {
        return;
    }

    try {
        auto & logger = *get_base().get_logger();

        if (!snapper_) {
            logger.debug("SnapperPlugin::post_transaction() - snapper connection not available, skipping");
            return;
        }

        const auto & packages = transaction.get_transaction_packages();
        logger.debug(
            "SnapperPlugin::post_transaction() - transaction processed {} package operations", packages.size());

        if (!pre_snapshot_num_.has_value()) {
            logger.debug("SnapperPlugin::post_transaction() - no pre-snapshot found, skipping post-snapshot creation");
            return;
        }

        unsigned int pre_num = pre_snapshot_num_.value();
        logger.info(
            "SnapperPlugin::post_transaction() - creating post-transaction snapshot (paired with #{})", pre_num);

        FilterDecision filter_decision;
        if (stored_filter_decision_.has_value()) {
            filter_decision = stored_filter_decision_.value();
            logger.debug("SnapperPlugin::post_transaction() - using stored FilterDecision for consistent metadata");
        } else {
            filter_decision = analyzeTransactionForSnapshot(transaction);
            logger.warning(
                "SnapperPlugin::post_transaction() - no stored FilterDecision found, re-analyzing transaction");
        }

        std::string description = generateSnapshotDescription(transaction, "post");
        logger.debug("SnapperPlugin::post_transaction() - snapshot description: {}", description);

        snapper::SCD scd;
        scd.description = description;

        if (filter_decision.is_important_transaction) {
            scd.cleanup = "important";
            logger.info(
                "SnapperPlugin::post_transaction() - using 'important' cleanup algorithm for important transaction");
        } else {
            scd.cleanup = config_.cleanup_algorithm;
        }

        scd.uid = 0;

        addTransactionMetadata(scd, transaction);

        if (filter_decision.is_important_transaction && !filter_decision.important_packages.empty()) {
            std::string imp_packages;
            for (size_t i = 0; i < filter_decision.important_packages.size(); ++i) {
                if (i > 0)
                    imp_packages += ",";
                imp_packages += filter_decision.important_packages[i];
            }
            scd.userdata["imp"] = imp_packages;
        }

        scd.userdata["transaction-result"] = "success";
        scd.userdata["paired-with"] = std::to_string(pre_num);

        logger.debug("SnapperPlugin::post_transaction() - looking up pre-snapshot #{} for pairing", pre_num);
        const auto & snapshots = snapper_->getSnapshots();
        auto pre_iter = std::find_if(snapshots.begin(), snapshots.end(), [pre_num](const snapper::Snapshot & snap) {
            return snap.getNum() == pre_num;
        });

        if (pre_iter == snapshots.end()) {
            logger.error(
                "SnapperPlugin::post_transaction() - pre-snapshot #{} not found, cannot create paired post-snapshot",
                pre_num);
            pre_snapshot_num_.reset();
            stored_filter_decision_.reset();
            return;
        }

        if (config_.dryrun) {
            pre_snapshot_num_.reset();
            stored_filter_decision_.reset();
            return;
        }

        logger.debug(
            "SnapperPlugin::post_transaction() - calling snapper->createPostSnapshot() with pre-snapshot #{}", pre_num);
        snapper::Plugins::Report report;
        auto snapshot_iter = snapper_->createPostSnapshot(pre_iter, scd, report);

        unsigned int post_num = snapshot_iter->getNum();

        logger.info(
            "SnapperPlugin::post_transaction() - created post-transaction snapshot #{} (paired with #{})",
            post_num,
            pre_num);
        logger.debug(
            "SnapperPlugin::post_transaction() - snapshot #{} created successfully with description: {}",
            post_num,
            description);

        if (!report.entries.empty()) {
            logger.debug(
                "SnapperPlugin::post_transaction() - snapshot creation report has {} entries", report.entries.size());
            for (const auto & entry : report.entries) {
                logger.debug(
                    "SnapperPlugin::post_transaction() - report: {} (exit: {})", entry.name, entry.exit_status);
            }
        }

        pre_snapshot_num_.reset();
        stored_filter_decision_.reset();
        logger.debug(
            "SnapperPlugin::post_transaction() - cleared pre-snapshot number and FilterDecision after successful "
            "pairing");
    } catch (const snapper::Exception & ex) {
        auto & logger = *get_base().get_logger();
        logger.error("SnapperPlugin::post_transaction() snapper error: {}", ex.what());
        logger.error(
            "SnapperPlugin::post_transaction() - failed to create post-snapshot, pre-snapshot #{} remains unpaired",
            pre_snapshot_num_.has_value() ? pre_snapshot_num_.value() : 0);
        pre_snapshot_num_.reset();
        stored_filter_decision_.reset();
    } catch (const std::exception & ex) {
        auto & logger = *get_base().get_logger();
        logger.error("SnapperPlugin::post_transaction() error: {}", ex.what());
        logger.error(
            "SnapperPlugin::post_transaction() - failed to create post-snapshot, pre-snapshot #{} remains unpaired",
            pre_snapshot_num_.has_value() ? pre_snapshot_num_.value() : 0);
        pre_snapshot_num_.reset();
        stored_filter_decision_.reset();
    }
}

void SnapperPlugin::load_config(libdnf5::ConfigParser & parser) {
    config_.enabled = true;
    config_.dryrun = false;
    config_.snapper_config = "root";
    config_.cleanup_algorithm = "number";
    config_.root_prefix = "/";

    try {
        const std::string config_file_path = "/etc/dnf/libdnf5-plugins/snapper.conf";
        try {
            parser.read(config_file_path);
        } catch (const std::exception & ex) {
            config_error_message_ += fmt::format("Could not read config file '{}': {} ", config_file_path, ex.what());
        }

        if (parser.has_section("main")) {
            if (parser.has_option("main", "enabled")) {
                const auto & enabled_str = parser.get_value("main", "enabled");
                std::string lower_str = enabled_str;
                std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);

                if (lower_str == "true" || lower_str == "1" || lower_str == "yes" || lower_str == "on") {
                    config_.enabled = true;
                } else if (lower_str == "false" || lower_str == "0" || lower_str == "no" || lower_str == "off") {
                    config_.enabled = false;
                } else {
                    config_error_message_ +=
                        fmt::format("Invalid 'enabled' value '{}', using default 'true'. ", enabled_str);
                }
            }

            if (parser.has_option("main", "dryrun")) {
                const auto & dryrun_str = parser.get_value("main", "dryrun");
                std::string lower_str = dryrun_str;
                std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);

                if (lower_str == "true" || lower_str == "1" || lower_str == "yes" || lower_str == "on") {
                    config_.dryrun = true;
                } else if (lower_str == "false" || lower_str == "0" || lower_str == "no" || lower_str == "off") {
                    config_.dryrun = false;
                } else {
                    config_error_message_ +=
                        fmt::format("Invalid 'dryrun' value '{}', using default 'false'. ", dryrun_str);
                }
            }

            if (parser.has_option("main", "snapper_config")) {
                const auto & snapper_config_str = parser.get_value("main", "snapper_config");
                if (!snapper_config_str.empty()) {
                    config_.snapper_config = snapper_config_str;
                } else {
                    config_error_message_ += "Empty 'snapper_config' value, using default 'root'. ";
                }
            }

            if (parser.has_option("main", "cleanup_algorithm")) {
                const auto & cleanup_str = parser.get_value("main", "cleanup_algorithm");
                if (cleanup_str == "number" || cleanup_str == "timeline" || cleanup_str == "empty-pre-post") {
                    config_.cleanup_algorithm = cleanup_str;
                } else if (!cleanup_str.empty()) {
                    config_.cleanup_algorithm = cleanup_str;
                    config_error_message_ +=
                        fmt::format("Unknown 'cleanup_algorithm' value '{}', using anyway. ", cleanup_str);
                } else {
                    config_error_message_ += "Empty 'cleanup_algorithm' value, using default 'number'. ";
                }
            }

            if (parser.has_option("main", "root_prefix")) {
                const auto & root_prefix_str = parser.get_value("main", "root_prefix");
                if (!root_prefix_str.empty()) {
                    config_.root_prefix = root_prefix_str;
                } else {
                    config_error_message_ += "Empty 'root_prefix' value, using default '/'. ";
                }
            }
        }

        if (config_.snapper_config.empty()) {
            config_.snapper_config = "root";
            config_error_message_ += "Snapper config name cannot be empty, using 'root'. ";
        }

        if (config_.root_prefix.empty()) {
            config_.root_prefix = "/";
            config_error_message_ += "Root prefix cannot be empty, using '/'. ";
        }

    } catch (const std::exception & ex) {
        config_error_message_ += fmt::format("Configuration parsing failed: {}", ex.what());

        config_.enabled = true;
        config_.dryrun = false;
        config_.snapper_config = "root";
        config_.cleanup_algorithm = "number";
        config_.root_prefix = "/";
    }

    loadFilterConfig(parser);
}

std::string SnapperPlugin::generateSnapshotDescription(
    [[maybe_unused]] const libdnf5::base::Transaction & transaction, const std::string & type) {
    std::string caller = getCallerProgram();
    return fmt::format("libdnf5({}) transaction ({})", caller, type);
}

std::map<std::string, int> SnapperPlugin::collectTransactionCounts(
    const libdnf5::base::Transaction & transaction) const {
    std::map<std::string, int> counts{
        {"install", 0}, {"upgrade", 0}, {"remove", 0}, {"downgrade", 0}, {"reinstall", 0}, {"other", 0}};

    const auto & packages = transaction.get_transaction_packages();
    for (const auto & pkg : packages) {
        switch (pkg.get_action()) {
            case libdnf5::transaction::TransactionItemAction::INSTALL:
                counts["install"]++;
                break;
            case libdnf5::transaction::TransactionItemAction::UPGRADE:
                counts["upgrade"]++;
                break;
            case libdnf5::transaction::TransactionItemAction::REMOVE:
                counts["remove"]++;
                break;
            case libdnf5::transaction::TransactionItemAction::DOWNGRADE:
                counts["downgrade"]++;
                break;
            case libdnf5::transaction::TransactionItemAction::REINSTALL:
                counts["reinstall"]++;
                break;
            default:
                counts["other"]++;
                break;
        }
    }

    return counts;
}

std::string SnapperPlugin::getCallerProgram() const {
    try {
        pid_t our_pid = getpid();
        std::string proc_path = fmt::format("/proc/{}/comm", our_pid);
        std::ifstream comm_file(proc_path);
        if (!comm_file.is_open()) {
            return "unknown";
        }

        std::string program_name;
        if (std::getline(comm_file, program_name) && !program_name.empty()) {
            program_name.erase(
                std::remove_if(program_name.begin(), program_name.end(), [](char c) { return c < 32 || c > 126; }),
                program_name.end());
            return program_name.empty() ? "unknown" : program_name;
        }
    } catch (...) {
    }
    return "unknown";
}

void SnapperPlugin::addTransactionMetadata(snapper::SCD & scd, const libdnf5::base::Transaction & transaction) const {
    auto operation_counts = collectTransactionCounts(transaction);

    const char * user_env = std::getenv("USER");
    const char * sudo_user_env = std::getenv("SUDO_USER");

    if (sudo_user_env && std::strlen(sudo_user_env) > 0 && std::strlen(sudo_user_env) <= 256) {
        std::string sudo_str(sudo_user_env);
        if (std::all_of(
                sudo_str.begin(), sudo_str.end(), [](char c) { return std::isalnum(c) || c == '_' || c == '-'; })) {
            if (!user_env || std::string(user_env) != sudo_str) {
                scd.userdata["sudo"] = sudo_str;
            }
        }
    }

    std::vector<std::string> ops;
    for (const auto & count_entry : operation_counts) {
        if (count_entry.second > 0) {
            const std::string & op = count_entry.first;
            if (op == "install")
                ops.push_back(fmt::format("i{}", count_entry.second));
            else if (op == "remove")
                ops.push_back(fmt::format("r{}", count_entry.second));
            else if (op == "upgrade")
                ops.push_back(fmt::format("u{}", count_entry.second));
            else if (op == "downgrade")
                ops.push_back(fmt::format("d{}", count_entry.second));
            else if (op == "reinstall")
                ops.push_back(fmt::format("re{}", count_entry.second));
        }
    }

    if (!ops.empty()) {
        std::string ops_str;
        for (size_t i = 0; i < ops.size(); ++i) {
            if (i > 0)
                ops_str += ",";
            ops_str += ops[i];
        }
        scd.userdata["ops"] = ops_str;
    }
}

void SnapperPlugin::loadFilterConfig(libdnf5::ConfigParser & parser) {
    try {
        size_t original_pattern_count = 0;
        size_t validated_pattern_count = 0;

        std::vector<std::string> include_patterns;
        std::vector<std::string> exclude_patterns;
        std::vector<std::string> important_patterns;

        if (parser.has_section("filters")) {
            if (parser.has_option("filters", "include_packages")) {
                const auto & include_str = parser.get_value("filters", "include_packages");
                if (!include_str.empty()) {
                    auto raw_patterns = parsePatternList(include_str);
                    original_pattern_count += raw_patterns.size();
                    include_patterns = raw_patterns;
                }
            }

            if (parser.has_option("filters", "exclude_packages")) {
                const auto & exclude_str = parser.get_value("filters", "exclude_packages");
                if (!exclude_str.empty()) {
                    auto raw_patterns = parsePatternList(exclude_str);
                    original_pattern_count += raw_patterns.size();
                    exclude_patterns = raw_patterns;
                }
            }

            if (parser.has_option("filters", "important_packages")) {
                const auto & important_str = parser.get_value("filters", "important_packages");
                if (!important_str.empty()) {
                    auto raw_patterns = parsePatternList(important_str);
                    original_pattern_count += raw_patterns.size();
                    important_patterns = raw_patterns;
                }
            }
        }

        package_filter_.setIncludePatterns(include_patterns);
        package_filter_.setExcludePatterns(exclude_patterns);
        package_filter_.setImportantPatterns(important_patterns);

        auto final_stats = package_filter_.getStats();
        validated_pattern_count =
            final_stats.include_patterns + final_stats.exclude_patterns + final_stats.important_patterns;

        if (original_pattern_count != validated_pattern_count) {
            config_error_message_ += fmt::format(
                "Security: {} invalid/dangerous patterns were filtered out ({}/{} patterns accepted). ",
                original_pattern_count - validated_pattern_count,
                validated_pattern_count,
                original_pattern_count);
        }
    } catch (const std::exception & ex) {
        config_error_message_ += fmt::format("Filter configuration parsing failed: {}", ex.what());
        package_filter_.setIncludePatterns({});
        package_filter_.setExcludePatterns({});
        package_filter_.setImportantPatterns({});
    }
}

std::vector<std::string> SnapperPlugin::parsePatternList(const std::string & pattern_string) const {
    std::vector<std::string> patterns;

    if (pattern_string.empty()) {
        return patterns;
    }

    std::istringstream iss(pattern_string);
    std::string pattern;

    while (std::getline(iss, pattern, ',')) {
        pattern.erase(0, pattern.find_first_not_of(" \t\n\r"));
        pattern.erase(pattern.find_last_not_of(" \t\n\r") + 1);

        if (!pattern.empty()) {
            patterns.push_back(pattern);
        }
    }

    if (patterns.empty()) {
        std::istringstream space_iss(pattern_string);
        while (space_iss >> pattern) {
            patterns.push_back(pattern);
        }
    }

    return patterns;
}

SnapperPlugin::FilterDecision SnapperPlugin::analyzeTransactionForSnapshot(
    const libdnf5::base::Transaction & transaction) const {
    FilterDecision decision;
    const auto & packages = transaction.get_transaction_packages();
    decision.total_packages = packages.size();

    if (packages.empty()) {
        return decision;
    }

    for (const auto & pkg : packages) {
        std::string package_name = pkg.get_package().get_name();

        auto analysis = package_filter_.analyzePackage(package_name);

        if (analysis.should_create_snapshot) {
            decision.matching_packages.push_back(package_name);
            decision.should_create_snapshot = true;
        } else {
            if (analysis.matches_exclude) {
                decision.excluded_packages.push_back(package_name);
            } else {
                decision.ignored_packages.push_back(package_name);
            }
        }

        if (analysis.is_important) {
            decision.important_packages.push_back(package_name);
            decision.is_important_transaction = true;
        }
    }

    return decision;
}

}  // anonymous namespace

extern "C" {
libdnf5::PluginAPIVersion libdnf_plugin_get_api_version(void) {
    return REQUIRED_PLUGIN_API_VERSION;
}

const char * libdnf_plugin_get_name(void) {
    return PLUGIN_NAME;
}

libdnf5::plugin::Version libdnf_plugin_get_version(void) {
    return PLUGIN_VERSION;
}

libdnf5::plugin::IPlugin * libdnf_plugin_new_instance(
    [[maybe_unused]] libdnf5::LibraryVersion library_version,
    libdnf5::plugin::IPluginData & data,
    libdnf5::ConfigParser & parser) try {
    return new SnapperPlugin(data, parser);
} catch (...) {
    last_exception = std::current_exception();
    return nullptr;
}

void libdnf_plugin_delete_instance(libdnf5::plugin::IPlugin * plugin_object) {
    delete plugin_object;
}

std::exception_ptr * libdnf_plugin_get_last_exception(void) {
    return &last_exception;
}
}