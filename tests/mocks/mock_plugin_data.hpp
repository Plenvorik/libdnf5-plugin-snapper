// Copyright (C) 2025 Andre Herrlich <plenvorik@gmail.com>
// SPDX-License-Identifier: LGPL-2.1-or-later

#ifndef MOCK_PLUGIN_DATA_HPP
#define MOCK_PLUGIN_DATA_HPP

#include <libdnf5/base/base.hpp>
#include <libdnf5/logger/logger.hpp>
#include <libdnf5/logger/memory_buffer_logger.hpp>
#include <memory>

/**
 * @brief Simplified mock for testing plugin functionality
 *
 * Since IPluginData is only forward-declared in the headers,
 * we create a simple wrapper that provides the minimal interface
 * needed for testing without full inheritance.
 */
class MockPluginData {
public:
    MockPluginData() {
        // Create a minimal Base instance for testing
        base_ = std::make_unique<libdnf5::Base>();

        // Initialize with a memory buffer logger for testing
        auto logger = std::make_unique<libdnf5::MemoryBufferLogger>();
        logger->set_level(libdnf5::Logger::Level::DEBUG);
        base_->set_logger(std::move(logger));
    }

    ~MockPluginData() = default;

    // Provide access to the base - used by tests
    libdnf5::Base& get_base() {
        return *base_;
    }

    // Test helper methods
    void set_log_level(libdnf5::Logger::Level level) {
        base_->get_logger()->set_level(level);
    }

    void reset_base() {
        base_ = std::make_unique<libdnf5::Base>();
    }

    // Get log output for testing
    std::string get_log_output() const {
        auto* memory_logger = dynamic_cast<libdnf5::MemoryBufferLogger*>(base_->get_logger());
        return memory_logger ? memory_logger->get_content() : "";
    }

    void clear_log() {
        auto* memory_logger = dynamic_cast<libdnf5::MemoryBufferLogger*>(base_->get_logger());
        if (memory_logger) {
            memory_logger->clear();
        }
    }

private:
    std::unique_ptr<libdnf5::Base> base_;
};

#endif // MOCK_PLUGIN_DATA_HPP