# Pyx: 결정론적 PostgreSQL 와이어 프로토콜 프록시 & 쿼리 게이트키퍼

[English](README.md) · [라이선스](LICENSE)

Pyx는 순수 Go 표준 라이브러리만으로 PostgreSQL 3.0 프론트엔드/백엔드 와이어 프로토콜을 구현한 제로 의존성 초저지연 TCP 프록시입니다. 애플리케이션 서비스와 PostgreSQL 데이터베이스 인스턴스 사이에 투명하게 위치하여 단순 쿼리(`Q`)와 확장 쿼리(`P`/`B`/`D`/`E`/`C`/`S`) 트래픽을 와이어 레벨에서 검사하고, 위험한 DDL, 테이블 리라이트, 대규모 변경 쿼리가 데이터베이스 엔진에 도달하기 전에 선제적으로 차단합니다.

## 아키텍처 개요

```
애플리케이션 / 서비스
        |  PostgreSQL 3.0 와이어 프로토콜 ('Q', 'P', 'B', 'D', 'E', 'C', 'S')
        v
+-------------------------------------------------------------------+
| Pyx 와이어 게이트키퍼 (:5433)                                     |
|                                                                   |
| 1. 양방향 와이어 프레이밍 및 핸드셰이크                           |
|    - SSLRequest / GSSENCRequest / CancelRequest 처리              |
|    - 확장 쿼리 프로토콜 상태 머신 (Parse/Bind/Execute/Close/Sync) |
|    - Prepared Statement 및 세션 lock_timeout 상태 추적            |
|                                                                   |
| 2. SQL 인식 렉서 및 정책 게이트키퍼                               |
|    - 주석(--, 중첩 /* */), 문자열 및 $tag$ 리터럴 오탐 제거       |
|    - lock_timeout 미설정 / 0 / 상한 초과 테이블 락 DDL 차단       |
|    - 전체 테이블 리라이트 DDL (ALTER COLUMN TYPE, volatile DEFAULT)|
|    - CONCURRENTLY 없는 인덱스 생성/삭제 및 VACUUM (FULL) 차단     |
|    - WHERE 누락 및 항진(1=1, TRUE) 대규모 UPDATE / DELETE 차단    |
|    - DROP DATABASE / DROP SCHEMA CASCADE 차단                     |
|                                                                   |
| 3. 정책 집행 및 텔레메트리                                        |
|    - Strict 모드: 네이티브 ErrorResponse('E') 합성 및 Sync 복구   |
|    - Audit 모드: 패킷 전달 및 구조화된 NDJSON 감사 로그 출력      |
|    - 실시간 /metrics JSON 엔드포인트 및 지연시간 백분위수 측정    |
+-------------------------------------------------------------------+
        |  안전한 쿼리만 통과 (Strict 모드)
        v
PostgreSQL 데이터베이스 인스턴스 (:5432)
```

## 듀얼 운영 프로시저

### 1. 엄격 차단 모드 (`--mode strict`)
- 단순 쿼리와 확장 쿼리(Prepared Statement) 모두에서 정책 위반 쿼리를 즉시 차단하고 네이티브 `ErrorResponse`를 반환합니다.
- 확장 쿼리 차단 시 후속 `Bind`/`Describe`/`Execute` 패킷을 `Sync`까지 안전하게 흡수하여 백엔드와 클라이언트 간 프로토콜 동기화를 유지합니다.

### 2. 감사 모드 (`--mode audit`)
- 모든 쿼리를 백엔드 PostgreSQL로 전달하면서 위험 쿼리 감지 내역과 지연시간 메트릭을 집계하고 `--audit-log`로 NDJSON 감사 로그를 기록합니다.

## 설치 및 빌드

Go 1.23 이상이 필요합니다:

```bash
git clone https://github.com/Aetherx86/Pyx.git
cd Pyx
go build -o bin/pyx ./cmd/pyx
```

## CLI 사용법

```bash
# 엄격 차단 모드 + NDJSON 감사 로그 + HTTP 메트릭 엔드포인트 실행
./bin/pyx \
  --listen :5433 \
  --target localhost:5432 \
  --mode strict \
  --max-lock-timeout 5s \
  --audit-log pyx-audit.ndjson \
  --metrics-addr 127.0.0.1:9090 \
  --report-json pyx-summary.json

# 단일 SQL 쿼리 사전 검증
./bin/pyx --inspect "ALTER TABLE users ADD COLUMN age integer;"

# 마이그레이션 SQL 파일 JSON 리포트 출력
./bin/pyx --inspect-file migration.sql --policy policy.json --format json
```

## 검증

```bash
go vet ./...
go test -v -race -cover ./...
python3 .github/scripts/repo_guard.py . --strict
```

## 라이선스

MIT License. Copyright (c) 2026 Jeong Hoon Kim (Aether Systems & Research Lab).
