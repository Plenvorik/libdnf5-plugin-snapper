// Copyright (C) 2025 Andre Herrlich <plenvorik@gmail.com>
// SPDX-License-Identifier: LGPL-2.1-or-later

/**
 * @file test_main.cpp
 * @brief Main entry point for Catch2 unit tests
 */

#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

// Catch2 v2 compatibility
#ifndef CATCH_VERSION_MAJOR
#define CATCH_VERSION_MAJOR 2
#endif

// Test configuration and global setup can go here if needed