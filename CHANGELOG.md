# Changelog

All notable changes are documented here.

## [Unreleased]

## [0.1.0] - 2026-09-08

### Added

- CO-RE eBPF telemetry foundation with libbpf skeleton loading.
- Process execution and exit observation.
- IPv4/IPv6 `connect(2)` attempt telemetry.
- `openat(2)` attempt telemetry with bounded pathname capture.
- BPF ring-buffer transport with reserve-failure accounting.
- Kernel-side PID/UID filters and userspace command-name filtering.
- NDJSON schema-1 event output and graceful shutdown.
- Strict compiler warnings, unit tests, ASan/UBSan, CI Gate and CodeQL.
- Privileged runtime smoke proving real BPF load/attach and exec/connect telemetry on Ubuntu 24.04.
- Versioned builds with `kernwatch --version`.
- Tag-driven source release packaging with SHA256 checksums.

### Changed

- Removed unproven parent-process and exit-status fields instead of emitting misleading values.
- Clarified the split source-license boundary: userspace/repository Apache-2.0, kernel BPF source GPL-2.0-only.

### Distribution

- v0.1.0 ships source archives, not a prebuilt combined executable. Binary packaging is deferred until the embedded BPF/userspace licensing boundary is reviewed explicitly.

[0.1.0]: https://github.com/mkarson1997/karzoun-kernwatch/releases/tag/v0.1.0
