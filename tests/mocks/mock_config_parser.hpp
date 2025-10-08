// Copyright (C) 2025 Andre Herrlich <plenvorik@gmail.com>
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef MOCK_CONFIG_PARSER_HPP
#define MOCK_CONFIG_PARSER_HPP

#include <libdnf5/conf/config_parser.hpp>
#include <map>
#include <string>
#include <stdexcept>

/**
 * @brief Mock implementation of ConfigParser for controlled testing
 *
 * This mock allows precise control over configuration input during tests,
 * enabling validation of various configuration scenarios including error cases.
 */
class MockConfigParser : public libdnf5::ConfigParser {
public:
    MockConfigParser() = default;
    ~MockConfigParser() override = default;

    // ConfigParser interface implementation
    void read(const std::string& file_path) override {
        if (simulate_file_error_) {
            throw std::runtime_error("Simulated file read error for: " + file_path);
        }
        last_file_path_ = file_path;
    }

    bool has_section(const std::string& section) const override {
        return sections_.find(section) != sections_.end();
    }

    bool has_option(const std::string& section, const std::string& key) const override {
        auto section_it = sections_.find(section);
        if (section_it == sections_.end()) {
            return false;
        }
        return section_it->second.find(key) != section_it->second.end();
    }

    const std::string& get_value(const std::string& section, const std::string& key) const override {
        auto section_it = sections_.find(section);
        if (section_it == sections_.end()) {
            throw std::runtime_error("Section not found: " + section);
        }

        auto key_it = section_it->second.find(key);
        if (key_it == section_it->second.end()) {
            throw std::runtime_error("Key not found: " + key + " in section: " + section);
        }

        return key_it->second;
    }

    // Mock control methods for testing
    void add_section(const std::string& section) {
        sections_[section] = std::map<std::string, std::string>();
    }

    void add_option(const std::string& section, const std::string& key, const std::string& value) {
        if (sections_.find(section) == sections_.end()) {
            add_section(section);
        }
        sections_[section][key] = value;
    }

    void clear() {
        sections_.clear();
        last_file_path_.clear();
        simulate_file_error_ = false;
    }

    void simulate_file_error(bool enable = true) {
        simulate_file_error_ = enable;
    }

    const std::string& get_last_file_path() const {
        return last_file_path_;
    }

    // Helper methods for common test configurations
    void setup_default_config() {
        add_section("main");
        add_option("main", "enabled", "true");
        add_option("main", "dryrun", "false");
        add_option("main", "snapper_config", "root");
        add_option("main", "cleanup_algorithm", "number");
        add_option("main", "root_prefix", "/");
    }

    void setup_filter_config() {
        add_section("filters");
        add_option("filters", "include_packages", "htop, tree, kernel-*");
        add_option("filters", "exclude_packages", "*-debuginfo, *-debugsource");
        add_option("filters", "important_packages", "kernel-*, glibc*, systemd*");
    }

    void setup_invalid_config() {
        add_section("main");
        add_option("main", "enabled", "invalid_boolean");
        add_option("main", "dryrun", "");
        add_option("main", "snapper_config", "");
    }

private:
    std::map<std::string, std::map<std::string, std::string>> sections_;
    std::string last_file_path_;
    bool simulate_file_error_{false};
};

#endif // MOCK_CONFIG_PARSER_HPP