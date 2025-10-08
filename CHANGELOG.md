# Changelog

All notable changes to libdnf5-plugin-snapper will be documented in this file.

## [1.0.1] - 2025-10-08

### Changed
- Code cleanup: removed ~170 lines of redundant inline comments
- Removed unused deprecated functions from PackageFilter class

### Fixed
- Snapshot creation now respects snapper library defaults (read-only=true)
- Previously incorrectly forced read-write mode, now aligns with default snapper behavior

## [1.0.0] - 2025-09-30

### Added
- Initial release of libdnf5-plugin-snapper
- DNF5 plugin implementing IPlugin2_1 interface for automatic filesystem snapshots
- Pre/post transaction snapshot creation via direct libsnapper API
- INI configuration file support with package filtering
- Transaction metadata collection and important packages marking

## [0.3.0] - 2025-09-29

### Added
- Advanced features: DNF5 transaction groups integration
- Rollback metadata support
- Performance optimizations and extended configuration options

## [0.2.0] - 2025-09-28

### Added
- Enhanced features: package filtering with wildcards and regex
- Important packages marking
- Intelligent snapshot management with metadata collection

## [0.1.0] - 2025-09-27

### Added
- Basic plugin structure and DNF5 API integration
- Configuration parsing (INI format)
- Pre/post snapshot creation using libsnapper
- Error handling and logging
- CMake build system and RPM packaging

---

[1.0.1]: https://github.com/plenvorik/libdnf5-plugin-snapper/releases/tag/v1.0.1