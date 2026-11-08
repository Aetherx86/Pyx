# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-08

### Added
- Initial release of Pyx deterministic PostgreSQL wire-protocol proxy and query gatekeeper in Go.
- Wire-level framing for PostgreSQL 3.0 protocol parsing ('Q', 'P', 'B', 'E', 'Z', 'C', 'S').
- Zero-external-dependency gatekeeper inspecting table-locking DDL without lock timeouts, non-concurrent index operations, unqualified bulk mutations, and VACUUM FULL.
- Dual procedure execution: `--mode strict` (active wire-level rejection returning SQLSTATE 55P03/54000 ErrorResponse packets) vs `--mode audit` (passive logging and telemetry monitoring).
- Standalone CLI query inspector (`--inspect`).
- Deterministic mock TCP proxy test suite and zero-allocation message encoder.
