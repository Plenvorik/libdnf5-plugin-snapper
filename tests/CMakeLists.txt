# Unit tests for libdnf5-plugin-snapper
# Copyright (C) 2025 Andre Herrlich <plenvorik@gmail.com>
# SPDX-License-Identifier: LGPL-2.1-or-later

cmake_minimum_required(VERSION 3.18)

# Find Catch2 testing framework (try v3 first, then v2)
find_package(Catch2 3 QUIET)
if(NOT Catch2_FOUND)
    find_package(Catch2 2 QUIET)
    if(NOT Catch2_FOUND)
        # Try pkg-config approach for Catch2
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(CATCH2 catch2)
        endif()

        if(NOT CATCH2_FOUND)
            message(WARNING "Catch2 not found - using basic test implementation")
            # Create basic test that works without Catch2
            add_executable(basic_test ../tests/test_basic.cpp)
            add_test(NAME basic_infrastructure_test COMMAND basic_test)
            return()
        endif()
    endif()
endif()

# Enable testing
enable_testing()

# Create a library from plugin source for testing
# This allows us to test internal functions without C linkage wrapper
add_library(snapper_plugin_lib STATIC
    ${CMAKE_SOURCE_DIR}/src/snapper_plugin.cpp
)

# Set library properties
target_include_directories(snapper_plugin_lib PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${LIBDNF5_INCLUDE_DIRS}
    ${LIBSNAPPER_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(snapper_plugin_lib PRIVATE
    ${LIBDNF5_LIBRARIES}
    ${LIBSNAPPER_LIBRARIES}
    ${Boost_LIBRARIES}
    fmt::fmt
)

target_compile_options(snapper_plugin_lib PRIVATE
    ${LIBDNF5_CFLAGS_OTHER}
    ${LIBSNAPPER_CFLAGS_OTHER}
)

# Define test sources
set(TEST_SOURCES
    test_minimal.cpp
    test_package_filter_direct.cpp
    test_advanced_features.cpp
    test_integration.cpp
    test_benchmarks.cpp
)

# Create test executable
add_executable(unit_tests
    ${TEST_SOURCES}
    test_main.cpp  # Custom main with Catch2
)

# Link test executable (temporarily without plugin lib to isolate issues)
target_link_libraries(unit_tests PRIVATE
    Catch2::Catch2
)

# Include directories for tests
target_include_directories(unit_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/mocks
    ${CMAKE_SOURCE_DIR}/src
    ${LIBDNF5_INCLUDE_DIRS}
    ${LIBSNAPPER_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
)

# Compile options for tests
target_compile_options(unit_tests PRIVATE
    ${LIBDNF5_CFLAGS_OTHER}
    ${LIBSNAPPER_CFLAGS_OTHER}
)

# Register tests with CTest
if(Catch2_VERSION VERSION_GREATER_EQUAL "3.0.0")
    include(Catch)
    catch_discover_tests(unit_tests)
else()
    # Catch2 v2 compatibility
    include(ParseAndAddCatchTests)
    ParseAndAddCatchTests(unit_tests)
endif()

# Add manual test runner
add_test(NAME unit_tests_manual COMMAND unit_tests)

# Test with verbose output
add_test(NAME unit_tests_verbose COMMAND unit_tests --success)

# Performance tests (longer timeout)
add_test(NAME unit_tests_performance COMMAND unit_tests "[performance]")
set_tests_properties(unit_tests_performance PROPERTIES TIMEOUT 30)

# Memory test with basic validation
add_test(NAME unit_tests_memory COMMAND unit_tests "[memory]")

message(STATUS "Test configuration:")
message(STATUS "  Catch2 version: ${Catch2_VERSION}")
message(STATUS "  Test sources: ${TEST_SOURCES}")
message(STATUS "  Tests will be registered with CTest")