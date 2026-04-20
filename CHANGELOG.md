# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-04-20

### Added

- MIT license and changelog tracking.
- `--version` flag with embedded build metadata.
- Goreleaser-based release automation with archives and checksums.
- Batch input support from files and stdin.
- Multi-target JSON and TXT export behavior.
- Race detector coverage in CI.
- Manual live integration workflow and integration test harness.
- Homebrew tap publishing and Scoop bucket publishing via Goreleaser.
- Release SBOM generation for published archives.
- Sigstore-signed checksum bundles for releases.
- GitHub provenance attestations for release artifacts.
- Optional macOS signing/notarization wiring for future Apple credentials.

## [1.0.1] - 2026-04-20

### Added

- Fixture-backed parser tests for all passive sources.
- Source health reporting for enabled, disabled, degraded, auth-required, and rate-limited states.
- Wildcard DNS filtering during resolution.
- Rich JSON report metadata with timestamps, per-source timings, source attribution, and DNS details.

### Changed

- Improved passive source retry behavior with source-specific backoff profiles.
- Improved runtime output around provider failures and resolver behavior.
- Fixed GitHub Actions portability across Linux, macOS, and Windows.

## [1.0.0] - 2026-04-20

### Added

- Initial public release of `subscan`.
- Passive subdomain enumeration from multiple public sources.
- Optional DNS resolution, TXT export, and JSON export.
- Config file support, source selection flags, CI, and tagged releases.
