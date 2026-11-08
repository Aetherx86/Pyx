# Pyx: 결정론적 PostgreSQL 와이어 프로토콜 프록시 & 쿼리 게이트키퍼

[English](README.md) · [라이선스](LICENSE)

Pyx는 순수 Go 표준 라이브러리만으로 PostgreSQL 3.0 프론트엔드/백엔드 와이어 프로토콜을 구현한 제로 의존성 초저지연 TCP 프록시입니다. 애플리케이션 서비스와 PostgreSQL 데이터베이스 인스턴스 사이에 투명하게 위치하여 네트워크 와이어 레벨에서 쿼리 패킷을 가로채고, 위험한 DDL이나 대규모 변경 쿼리가 데이터베이스 스토리지 엔진에 도달하기 전에 선제적으로 차단합니다.

## 아키텍처 개요

```
애플리케이션 / 서비스
        |  PostgreSQL 3.0 와이어 프로토콜 ('Q', 'P', 'B', 'E')
        v
+-----------------------------------------------------------+
| Pyx 와이어 게이트키퍼 (:5433)                             |
|                                                           |
| 1. 패킷 프레이밍 및 쿼리 추출 (제로 힙 할당)              |
| 2. 게이트키퍼 위험 분석 엔진                              |
|    - lock_timeout 없는 테이블 락 DDL 차단                 |
|    - CONCURRENTLY 없는 인덱스 생성 및 삭제 차단           |
|    - WHERE 절 없는 대규모 UPDATE / DELETE 차단            |
|    - 전체 테이블 배타적 락을 유발하는 VACUUM FULL 차단    |
|                                                           |
| 3. 듀얼 프로시저 정책 결정:                               |
|    - Strict 모드: 네이티브 ErrorResponse('E') 합성 및 차단|
|    - Audit 모드: 텔레메트리 로깅 후 DB로 패킷 전달        |
+-----------------------------------------------------------+
        |  안전한 쿼리만 통과 (Strict 모드)
        v
PostgreSQL 데이터베이스 인스턴스 (:5432)
```

## 왜 와이어 레벨 차단인가?

CI 단계의 정적 마이그레이션 린터는 깃에 커밋된 스크립트만 검증할 수 있으며 다음과 같은 실제 운영 사고를 막지 못합니다:
1. 개발자가 프로덕션 콘솔에서 직접 실행하는 긴급 핫픽스 쿼리.
2. 애플리케이션 부트스트랩 시점에 ORM이 자동으로 트리거하는 동적 DDL.
3. API 버그나 잘못된 쿼리로 인해 WHERE 절 없이 유입되는 대량 DELETE/UPDATE.

Pyx는 네트워크 계층에서 쿼리를 직접 분석하여 위험한 연산을 감지하고, 네이티브 PostgreSQL `ErrorResponse` 패킷(SQLSTATE `55P03` / `54000`)으로 응답합니다. `libpq`, `pgx`, `node-postgres`, `asyncpg`, `psql` 등 모든 표준 데이터베이스 드라이버와 100% 호환됩니다.

## 듀얼 운영 프로시저

Pyx는 운영 목적에 따라 두 가지 실행 모드를 제공합니다:

### 1. 엄격 차단 모드 (`--mode strict`)
- 정책을 위반하는 위험한 쿼리가 감지되면 즉시 가로채어 클라이언트에 네이티브 `ErrorResponse`를 반환하고, 백엔드 데이터베이스로 패킷을 전송하지 않습니다.
- 스테이징 및 프로덕션 환경에서 장애를 원천 차단하기 위한 기본 모드입니다.

### 2. 감사 모드 (`--mode audit`)
- 모든 쿼리를 백엔드 PostgreSQL로 정상 전달하되, 정책 위반 쿼리가 감지되면 구조화된 NDJSON 텔레메트리 로그를 남깁니다.
- 기존 레거시 시스템의 쿼리 패턴을 모니터링하고 분석할 때 사용합니다.

## 설치 및 빌드

Go 1.23 이상이 필요합니다:

```bash
git clone https://github.com/Aetherx86/Pyx.git
cd Pyx
go build -o bin/pyx ./cmd/pyx
```

## CLI 사용법

```bash
# 기본 엄격 차단 모드로 5433 포트에서 프록시 실행 (백엔드 5432)
./bin/pyx --listen :5433 --target localhost:5432 --mode strict

# 실시간 패킷 전송 없이 단일 SQL 쿼리 사전 검증
./bin/pyx --inspect "ALTER TABLE users ADD COLUMN age integer;"
```

## 공급망 보안 검증

```bash
python3 .github/scripts/repo_guard.py . --strict
go test -v -race ./...
```

## 라이선스

MIT License. Copyright (c) 2026 Jeong Hoon Kim (Aether Systems & Research Lab).
