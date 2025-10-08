# libdnf5-plugin-snapper

[![CI Build](https://github.com/Plenvorik/libdnf5-plugin-snapper/actions/workflows/ci.yml/badge.svg)](https://github.com/Plenvorik/libdnf5-plugin-snapper/actions/workflows/ci.yml)
[![License: LGPL-2.1](https://img.shields.io/badge/License-LGPL%202.1-blue.svg)](COPYING)

**Automatic filesystem snapshots for DNF5 package transactions using Snapper.**

This plugin creates before/after snapshots of your system when installing, upgrading, or removing packages with DNF5, giving you an easy rollback option if something goes wrong.

## Why Use This?

- **Safety Net**: Automatically snapshot your system before risky upgrades
- **Easy Rollback**: Undo problematic package changes with Snapper's rollback
- **Smart Filtering**: Only snapshot when important packages change (kernel, systemd, etc.)
- **Fast & Native**: Uses libsnapper API directly, works in rescue mode
- **DNF5 Ready**: Modern replacement for the old python3-dnf-plugin-snapper

## Quick Start

### Installation

**From GitHub Releases:**
```bash
# Download the latest RPM from GitHub releases
wget https://github.com/Plenvorik/libdnf5-plugin-snapper/releases/latest/download/libdnf5-plugin-snapper-*.rpm

# Install
sudo dnf install ./libdnf5-plugin-snapper-*.rpm
```

**From Source:**
```bash
git clone https://github.com/Plenvorik/libdnf5-plugin-snapper.git
cd libdnf5-plugin-snapper
mkdir build && cd build
cmake ..
make
sudo make install
```

### Usage

Once installed, the plugin works automatically:

```bash
# Install a package - snapshots created automatically
sudo dnf install kernel

# Check your snapshots
sudo snapper list

# Rollback if needed
sudo snapper rollback <snapshot-number>
```

### Configuration

Edit `/etc/dnf/libdnf5-plugins/snapper.conf` to customize:

```ini
[main]
enabled = true
snapper_config = root
cleanup_algorithm = number

[filters]
# Snapshot only for important packages (recommended)
include_packages = *
important_packages = kernel-*, systemd*, grub2-*, glibc*
```

## How It Works

1. **Pre-Transaction**: Plugin checks if transaction affects filtered packages
2. **Snapshot Created**: If yes, creates a "pre" snapshot before changes
3. **Transaction Runs**: DNF installs/removes packages normally
4. **Post-Snapshot**: Creates paired "post" snapshot after success
5. **Metadata Stored**: Transaction details saved for later reference

## Contributing

Contributions welcome! Here's how to get involved:

### Report Issues
Found a bug? [Open an issue](https://github.com/Plenvorik/libdnf5-plugin-snapper/issues) with:
- Your Fedora version
- Steps to reproduce
- Expected vs actual behavior
- Output from `dnf -v install <package>`

### Submit Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/awesome-improvement`)
3. Make your changes (follow existing code style)
4. Run tests: `ctest` in build directory
5. Commit with clear message
6. Push and open a pull request

### Development Setup
```bash
# Install dependencies
sudo dnf install cmake gcc-c++ libdnf5-devel snapper-devel boost-devel fmt-devel catch2-devel

# Build with tests
cmake -B build -DENABLE_TESTS=ON
cmake --build build

# Run tests
cd build && ctest --verbose
```

## Requirements

- **Fedora 41+** or compatible distribution with DNF5
- **Snapper >= 0.10** with configured snapshot configuration
- **Btrfs filesystem** (or other filesystem supported by Snapper)

## Compatibility

This plugin replaces the older `python3-dnf-plugin-snapper` for DNF4. Configuration format is compatible but uses enhanced INI syntax.

## License

LGPL-2.1-or-later - see [COPYING](COPYING) for details.

## Authors

- **Andre Herrlich** - Current maintainer - [@Plenvorik](https://github.com/Plenvorik)
- Based on original dnf-plugin-snapper by Igor Gnatenko (2014)

## Links

- [GitHub Repository](https://github.com/Plenvorik/libdnf5-plugin-snapper)
- [Issue Tracker](https://github.com/Plenvorik/libdnf5-plugin-snapper/issues)
- [Releases](https://github.com/Plenvorik/libdnf5-plugin-snapper/releases)
- [Snapper Documentation](http://snapper.io/)
- [DNF5 Plugin API](https://github.com/rpm-software-management/dnf5)
