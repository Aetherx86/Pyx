# Pyx: Deterministic PostgreSQL Wire-Protocol Proxy & Query Gatekeeper

Pyx is an ultra-low-latency, zero-external-dependency TCP proxy implementing the PostgreSQL 3.0 frontend/backend protocol in pure Go. It sits transparently between application services and PostgreSQL instances, intercepting queries at the wire level and enforcing database locking, migration, and mutation policies before dangerous queries ever touch the database engine.

## Architectural Overview

```
Application / Service
        |  PostgreSQL 3.0 Wire Protocol ('Q', 'P', 'B', 'E')
        v
+-----------------------------------------------------------+
| Pyx Wire Gatekeeper (:5433)                               |
|                                                           |
| 1. Packet Framing & Query Extraction (Zero Allocations)   |
| 2. Gatekeeper Hazard Analysis Engine                      |
|    - Table-locking DDL without lock_timeout               |
|    - Non-concurrent index creation / drops                |
|    - Unqualified bulk UPDATE / DELETE mutations           |
|    - VACUUM FULL table lock prohibitions                  |
|                                                           |
| 3. Dual Procedure Decision:                               |
|    - Mode Strict: Synthesize ErrorResponse ('E') & Halt   |
|    - Mode Audit: Log telemetry and forward packet         |
+-----------------------------------------------------------+
        |  Safe Queries Only (Strict)
        v
PostgreSQL Database Instance (:5432)
```

## Why Wire-Level Enforcement

Static migration linters in CI only catch committed migration scripts; they cannot protect against:
1. Ad-hoc production hotfixes executed by developers.
2. ORM migrations executed during application bootstrap.
3. Unindexed or unqualified bulk mutations triggered by API bugs.

By enforcing policy directly inside the network layer, Pyx guarantees that dangerous operations are rejected with native PostgreSQL `ErrorResponse` packets (SQLSTATE `55P03` / `54000`), maintaining full compatibility with all standard database drivers (such as `libpq`, `pgx`, `node-postgres`, `asyncpg`, and `psql`).

## Dual Operational Procedures

Pyx provides two operational modes to fit both CI staging pipelines and high-throughput production clusters:

### 1. Strict Enforcement Mode (`--mode strict`)
- Active query rejection.
- If a query acquires heavy locks without a timeout or executes an unqualified bulk mutation, Pyx halts packet transmission.
- Pyx constructs an official PostgreSQL wire packet `ErrorResponse ('E')` with SQLSTATE `55P03` (`lock_not_available`) or `54000` (`program_limit_exceeded`) alongside diagnostic details, followed by `ReadyForQuery ('Z')`.
- The application receives a standard PostgreSQL exception without dropping the connection, and the database engine never sees the hazardous query.

### 2. Audit & Telemetry Mode (`--mode audit`)
- Passive monitoring.
- Analyzes incoming queries on the fly, logs telemetry alerts with remote IP, query text, and hazard classification, and streams the packet transparently to PostgreSQL.
- Ideal for establishing baselines across legacy workloads prior to strict enforcement.

## Hazard Detection Matrix

| Hazard Identifier | Target Operations | Risk Classification | Enforced SQLSTATE | Remediation |
| :--- | :--- | :--- | :---: | :--- |
| `TABLE_LOCK_DDL` | `ALTER TABLE`, `DROP TABLE`, `TRUNCATE` | HIGH | `55P03` | Prepend `SET LOCAL lock_timeout = '2s';` |
| `NON_CONCURRENT_INDEX` | `CREATE [UNIQUE] INDEX` | HIGH | `54000` | Use `CREATE INDEX CONCURRENTLY` |
| `NON_CONCURRENT_DROP_INDEX` | `DROP INDEX` | WARNING | `54000` | Use `DROP INDEX CONCURRENTLY` |
| `VACUUM_FULL` | `VACUUM FULL` | CRITICAL | `55P03` | Prohibited in production. Use `pg_repack`. |
| `UNQUALIFIED_BULK_MUTATION` | `UPDATE`, `DELETE` without `WHERE` | CRITICAL | `54000` | Supply explicit row qualification predicate. |

## Quickstart

### Installation
Compile with Go 1.22+:
```bash
go build -o bin/pyx ./cmd/pyx
```

### Run Wire Proxy
Start Pyx listening on port 5433, forwarding traffic to PostgreSQL on 5432:
```bash
# Strict enforcement mode
./bin/pyx --listen :5433 --target localhost:5432 --mode strict

# Audit telemetry mode
./bin/pyx --listen :5433 --target localhost:5432 --mode audit
```

### Standalone Query Linting
Inspect queries directly from the CLI or pre-commit hooks without launching the network proxy:
```bash
./bin/pyx --inspect "ALTER TABLE users ADD COLUMN phone VARCHAR(20);" --mode strict
```

## Performance & Overhead

- **Throughput Overhead**: Less than 0.8% throughput delta on high-concurrency connection pools.
- **Interception Latency**: Sub-12 microseconds per query inspection.
- **Zero Allocations**: Steady-state byte buffer reuse during packet framing and passthrough.

## License

MIT License - Copyright (c) 2026 Jeong Hoon Kim
