# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-20

### Added
- SQL-aware zero-dependency PostgreSQL lexer (`pkg/gatekeeper/lexer.go`) handling `--` comments, nested `/* ... */` block comments, single-quoted and `E'...'` strings, double-quoted identifiers, dollar-quoted literals (`$tag$...$tag$`), and multi-statement splitting with 1-based line numbers.
- Connection/transaction `SessionState` (`pkg/gatekeeper/session.go`) tracking `BEGIN`/`COMMIT`/`ROLLBACK`, `SET [LOCAL|SESSION] lock_timeout`, `RESET`, and `set_config('lock_timeout', ...)` across queries and batches.
- Expanded SQL policy rules: `TABLE_REWRITE_DDL` (`ALTER COLUMN TYPE`, volatile `ADD COLUMN ... DEFAULT`), `DROP_DATABASE_OR_SCHEMA` (`DROP DATABASE`, `DROP SCHEMA ... CASCADE`), `LOCK_TIMEOUT_DISABLED` (preventing `lock_timeout = '0'` bypasses), `LOCK_TIMEOUT_EXCEEDED`, `VACUUM (FULL)` parenthesized options, `LOCK TABLE` (permitting `NOWAIT`), non-concurrent `REINDEX`, writable CTE mutation inspection, and tautological `WHERE` predicate detection (`TRUE`, `1=1`, `'a'='a'`, `... OR 1=1`) while permitting dynamic builder patterns (`WHERE 1=1 AND col = $1`).
- Configurable JSON `Policy` support (`--policy`, `--max-lock-timeout`) with rule disabling, table allowlists, and custom blocking severity thresholds.
- Stateful Extended Query Protocol handling (`Parse`, `Bind`, `Describe`, `Execute`, `Close`, `Sync`) with named prepared statement tracking, Bind-time session re-validation (TOCTOU prevention), wire-compliant error absorption until `Sync`, pipelined partial-batch error injection, and transaction status (`I`/`T`/`E`) preservation.
- Startup protocol handling for `GSSENCRequest`, `CancelRequest`, and v3.0 startup parameter extraction (`user`, `database`, `application_name`).
- Bounded-memory latency percentile tracker (`min`, `mean`, `p50`, `p95`, `p99`, `max` microseconds) for both gatekeeper inspection and backend execution, per-hazard-type counters, structured NDJSON audit logging (`--audit-log`), optional HTTP `/metrics` & `/healthz` server (`--metrics-addr`), and shutdown JSON report export (`--report-json`).
- Standalone SQL file/stdin inspection (`--inspect-file`) and JSON report output (`--format json`) in `cmd/pyx`.
- Comprehensive unit, protocol, CLI, and concurrent race-tested proxy integration test suites.

### Fixed
- `protocol.Packet.WriteTo` now conforms to `io.WriterTo` (`(int64, error)`), resolving `go vet` `stdmethods` errors and avoiding split writes on small frames via a stack buffer.
- Serialized client socket writes per connection and protected listener lifecycle fields under mutex to eliminate frame interleaving and startup/shutdown races.

## [0.1.0] - 2026-11-08

### Added
- Initial release of Pyx deterministic PostgreSQL wire-protocol proxy and query gatekeeper in Go.
- Wire-level framing for PostgreSQL 3.0 protocol parsing ('Q', 'P', 'B', 'E', 'Z', 'C', 'S').
- Zero-external-dependency gatekeeper inspecting table-locking DDL without lock timeouts, non-concurrent index operations, unqualified bulk mutations, and VACUUM FULL.
- Dual procedure execution: `--mode strict` (active wire-level rejection returning SQLSTATE 55P03/54000 ErrorResponse packets) vs `--mode audit` (passive logging and telemetry monitoring).
- Standalone CLI query inspector (`--inspect`).
- Deterministic mock TCP proxy test suite and zero-allocation message encoder.
