# Pyx: Deterministic PostgreSQL Wire-Protocol Proxy & Query Gatekeeper

Pyx is an ultra-low-latency, zero-external-dependency TCP proxy implementing the PostgreSQL 3.0 frontend/backend protocol in pure Go. It sits transparently between application services and PostgreSQL instances, intercepting simple and extended query traffic at the wire level and enforcing database locking, migration, table-rewrite, and mutation policies before dangerous statements reach the database engine.

## Architectural Overview

```
Application / Service
        |  PostgreSQL 3.0 Wire Protocol ('Q', 'P', 'B', 'D', 'E', 'C', 'S')
        v
+-------------------------------------------------------------------+
| Pyx Wire Gatekeeper (:5433)                                       |
|                                                                   |
| 1. Bidirectional Wire Framing & Handshake                         |
|    - SSLRequest / GSSENCRequest / CancelRequest handling          |
|    - Extended Query state machine (Parse/Bind/Execute/Close/Sync) |
|    - Prepared-statement & connection SessionState tracking        |
|                                                                   |
| 2. SQL-Aware Lexer & Policy Gatekeeper                            |
|    - Strips comments (--, nested /* */), string & $tag$ literals  |
|    - Table-locking DDL without bounded lock_timeout               |
|    - Full table-rewrite DDL (ALTER COLUMN TYPE, volatile DEFAULT) |
|    - Non-concurrent index creation / drops & VACUUM (FULL)        |
|    - Unqualified & tautological bulk UPDATE / DELETE mutations    |
|    - Destructive DROP DATABASE / DROP SCHEMA CASCADE              |
|                                                                   |
| 3. Enforcement & Telemetry                                        |
|    - Mode Strict: Synthesize ErrorResponse ('E') & Sync recovery  |
|    - Mode Audit: Forward packet and emit NDJSON audit telemetry   |
|    - Live /metrics JSON endpoint & latency percentile tracking    |
+-------------------------------------------------------------------+
        |  Safe Queries Only (Strict)
        v
PostgreSQL Database Instance (:5432)
```

## Why Wire-Level Enforcement

Static migration linters in CI only catch committed migration scripts; they cannot protect against:
1. Ad-hoc production hotfixes executed by operators.
2. ORM migrations executed during application bootstrap.
3. Unqualified or tautological bulk mutations triggered by application bugs or prepared statements.
4. Prepared-statement TOCTOU reuse after a transaction-local `lock_timeout` expires.

By enforcing policy directly inside the network layer, Pyx rejects hazardous operations with native PostgreSQL `ErrorResponse` packets (SQLSTATE `55P03`, `54000`, `42501`) while preserving transaction status (`I`/`T`/`E`) and extended query synchronization across `libpq`, `pgx`, `node-postgres`, `asyncpg`, JDBC, and `psql`.

## Dual Operational Procedures

Pyx provides two operational modes to fit both CI staging pipelines and high-throughput production clusters:

### 1. Strict Enforcement Mode (`--mode strict`)
- Active query rejection across both Simple (`Q`) and Extended (`P`/`B`/`D`/`E`/`S`) query protocols.
- For simple queries, Pyx halts forwarding and returns a native `ErrorResponse ('E')` followed by `ReadyForQuery ('Z')` matching the backend's active transaction state.
- For extended queries, Pyx absorbs trailing `Bind`/`Describe`/`Execute` messages until `Sync ('S')` (and handles pipelined partial batches cleanly) so the connection stays wire-synchronized without dropping or desynchronizing the backend.

### 2. Audit & Telemetry Mode (`--mode audit`)
- Passive monitoring.
- Inspects incoming traffic on the fly, records per-hazard counters and latency histograms, emits structured NDJSON audit events when `--audit-log` is configured, and forwards packets transparently to PostgreSQL.

## Hazard Detection Matrix

| Hazard Identifier | Target Operations | Severity | SQLSTATE | Remediation |
| :--- | :--- | :--- | :---: | :--- |
| `TABLE_LOCK_DDL` | `ALTER TABLE`, `DROP TABLE`, `TRUNCATE`, `LOCK TABLE` (without `NOWAIT`), `CLUSTER`, non-concurrent `REINDEX` without active `lock_timeout` | `ERROR` | `55P03` | Prepend `SET LOCAL lock_timeout = '2s';` |
| `LOCK_TIMEOUT_DISABLED` | Table-locking DDL while `lock_timeout` is explicitly `0` or `DEFAULT` | `ERROR` | `55P03` | Configure a positive bounded `lock_timeout` |
| `LOCK_TIMEOUT_EXCEEDED` | `lock_timeout` exceeding policy `max_lock_timeout` ceiling | `ERROR` | `55P03` | Lower `lock_timeout` within configured policy limit |
| `TABLE_REWRITE_DDL` | `ALTER TABLE ... ALTER COLUMN TYPE` or `ADD COLUMN ... DEFAULT <volatile_fn()>` | `ERROR` | `55P03` | Use expand-and-contract or nullable column + batched backfill |
| `NON_CONCURRENT_INDEX` | `CREATE [UNIQUE] INDEX` without `CONCURRENTLY` | `ERROR` | `54000` | Use `CREATE [UNIQUE] INDEX CONCURRENTLY` |
| `NON_CONCURRENT_DROP_INDEX` | `DROP INDEX` without `CONCURRENTLY` | `WARNING` | `54000` | Use `DROP INDEX CONCURRENTLY` |
| `VACUUM_FULL` | `VACUUM FULL` and `VACUUM (FULL ...)` | `ERROR` | `55P03` | Use standard `VACUUM` or `pg_repack` |
| `UNQUALIFIED_BULK_MUTATION` | `UPDATE`/`DELETE` (including aliases, `ONLY`, writable CTEs) with missing or tautological `WHERE` (`TRUE`, `1=1`, `'a'='a'`, `... OR 1=1`) | `ERROR` | `54000` | Supply a selective row-filtering `WHERE` predicate |
| `DROP_DATABASE_OR_SCHEMA` | `DROP DATABASE`, `DROP SCHEMA ... CASCADE` | `PANIC` (wire `ERROR`) | `42501` | Execute via controlled administrative runbooks |

## Quickstart

### Installation
Compile with Go 1.23+:
```bash
go build -o bin/pyx ./cmd/pyx
```

### Run Wire Proxy
Start Pyx listening on port 5433, forwarding traffic to PostgreSQL on 5432:
```bash
# Strict enforcement with NDJSON audit log and live /metrics HTTP endpoint
./bin/pyx \
  --listen :5433 \
  --target localhost:5432 \
  --mode strict \
  --max-lock-timeout 5s \
  --audit-log /var/log/pyx-audit.ndjson \
  --metrics-addr 127.0.0.1:9090 \
  --report-json /var/log/pyx-summary.json

# Audit telemetry mode
./bin/pyx --listen :5433 --target localhost:5432 --mode audit --audit-log -
```

### Standalone Query & Migration File Inspection
Inspect inline SQL strings, migration files, or stdin in CI pipelines and pre-commit hooks with human-readable text or structured JSON output:
```bash
# Inline query check
./bin/pyx --inspect "ALTER TABLE users ADD COLUMN phone VARCHAR(20);" --mode strict

# Inspect a SQL migration file as JSON with a lock_timeout cap
./bin/pyx --inspect-file db/migrations/0042.sql --max-lock-timeout 5s --format json

# Inspect from stdin using a policy file
cat migration.sql | ./bin/pyx --inspect-file - --policy policy.json --format json
```

### Policy Configuration (`--policy`)
```json
{
  "strict_mode": true,
  "block_severity": "ERROR",
  "max_lock_timeout": "5s",
  "disabled_rules": ["NON_CONCURRENT_DROP_INDEX"],
  "allowlisted_tables": ["scratch_imports", "staging.temp_events"]
}
```

### Live Telemetry Endpoints (`--metrics-addr`)
- `GET /metrics`: JSON snapshot including active/total connections, simple/extended query counts, allowed/blocked/audited counts, per-hazard-type breakdown, and microsecond latency percentiles (`min`, `mean`, `p50`, `p95`, `p99`, `max`) for both gatekeeper inspection and backend execution.
- `GET /healthz`: JSON liveness summary with active mode and connection counters.

## Verification

```bash
go vet ./...
go test -v -race -cover ./...
go build ./...
python3 .github/scripts/repo_guard.py . --strict
```

## License

MIT License - Copyright (c) 2026 Jeong Hoon Kim
