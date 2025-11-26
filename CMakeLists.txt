cmake_minimum_required(VERSION 3.18)

# Project Definition
project(libdnf5-plugin-snapper
    VERSION 1.0.2
    DESCRIPTION "Snapper plugin for DNF5 - automatic filesystem snapshots"
    LANGUAGES CXX)

# C++ Standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags - strict quality gates
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Werror=return-type -Werror=uninitialized -Wunused-function -Wshadow -Wnon-virtual-dtor")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2 -DNDEBUG")

# Find required packages
find_package(PkgConfig REQUIRED)

# libdnf5
pkg_check_modules(LIBDNF5 REQUIRED libdnf5>=5.0)

# libsnapper (no pkg-config in 0.11+, find manually)
# Require snapper >= 0.10 for snapper::Plugins::Report API
find_path(SNAPPER_INCLUDE_DIR snapper/Snapper.h)
find_library(SNAPPER_LIBRARY snapper)
if(NOT SNAPPER_INCLUDE_DIR OR NOT SNAPPER_LIBRARY)
    message(FATAL_ERROR "libsnapper >= 0.10 not found (required for snapper::Plugins::Report)")
endif()
set(LIBSNAPPER_INCLUDE_DIRS ${SNAPPER_INCLUDE_DIR})
set(LIBSNAPPER_LIBRARIES ${SNAPPER_LIBRARY})

# Boost (use modern CMake approach)
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.20")
    cmake_policy(SET CMP0167 NEW)
endif()
find_package(Boost REQUIRED COMPONENTS filesystem regex)

# fmt
find_package(fmt REQUIRED)

# Installation directories
include(GNUInstallDirs)

# Plugin installation directory
if(NOT DEFINED LIBDNF5_PLUGIN_DIR)
    set(LIBDNF5_PLUGIN_DIR "/usr/lib64/libdnf5/plugins")
endif()

# Configuration installation directory
if(NOT DEFINED PLUGIN_CONF_DIR)
    set(PLUGIN_CONF_DIR "/etc/dnf/libdnf5-plugins")
endif()

# Source files
set(PLUGIN_SOURCES
    src/snapper_plugin.cpp
)

# Create shared library (MODULE, not SHARED for plugins)
add_library(snapper_plugin MODULE ${PLUGIN_SOURCES})

# Set library properties - disable the 'lib' prefix to create snapper.so
set_target_properties(snapper_plugin PROPERTIES
    OUTPUT_NAME "snapper"
    PREFIX ""
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Include directories
target_include_directories(snapper_plugin PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LIBDNF5_INCLUDE_DIRS}
    ${LIBSNAPPER_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(snapper_plugin PRIVATE
    ${LIBDNF5_LIBRARIES}
    ${LIBSNAPPER_LIBRARIES}
    ${Boost_LIBRARIES}
    fmt::fmt
)

# Compile options
target_compile_options(snapper_plugin PRIVATE
    ${LIBDNF5_CFLAGS_OTHER}
    ${LIBSNAPPER_CFLAGS_OTHER}
)

# Install plugin
install(TARGETS snapper_plugin
    LIBRARY DESTINATION ${LIBDNF5_PLUGIN_DIR}
)

# Install configuration
install(FILES config/snapper.conf
    DESTINATION ${PLUGIN_CONF_DIR}
)

# Install documentation
install(FILES
    README.md
    CHANGELOG.md
    DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

# Testing (enabled by default)
option(ENABLE_TESTS "Enable testing" ON)
if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Package configuration
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY ${PROJECT_DESCRIPTION})
set(CPACK_PACKAGE_LICENSE "LGPL-2.1-or-later")
set(CPACK_GENERATOR "RPM")
set(CPACK_RPM_PACKAGE_REQUIRES "libdnf5 >= 5.0, snapper-libs >= 0.8")
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Base")

include(CPack)

# Print configuration
message(STATUS "")
message(STATUS "Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Plugin install dir: ${LIBDNF5_PLUGIN_DIR}")
message(STATUS "  Config install dir: ${PLUGIN_CONF_DIR}")
message(STATUS "  Testing: ${ENABLE_TESTS}")
message(STATUS "")