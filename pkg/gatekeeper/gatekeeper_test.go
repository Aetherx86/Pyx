package gatekeeper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGatekeeperTableLockDDL(t *testing.T) {
	gkStrict := New(true)
	gkAudit := New(false)

	dangerousDDL := "ALTER TABLE users ADD COLUMN phone_number VARCHAR(32);"
	hazards := gkStrict.Inspect(dangerousDDL)
	if len(hazards) == 0 {
		t.Fatalf("expected hazards on unconstrained ALTER TABLE, got none")
	}

	block, h := gkStrict.ShouldBlock(hazards)
	if !block {
		t.Fatalf("expected strict mode to block dangerous DDL")
	}
	if h.SQLState != "55P03" {
		t.Fatalf("expected SQLSTATE 55P03, got %s", h.SQLState)
	}

	blockAudit, _ := gkAudit.ShouldBlock(hazards)
	if blockAudit {
		t.Fatalf("expected audit mode not to block")
	}

	safeDDL := "SET LOCAL lock_timeout = '2s'; ALTER TABLE users ADD COLUMN phone_number VARCHAR(32);"
	safeHazards := gkStrict.Inspect(safeDDL)
	if len(safeHazards) != 0 {
		t.Fatalf("expected 0 hazards for safe DDL with lock_timeout, got %d: %+v", len(safeHazards), safeHazards)
	}
}

func TestGatekeeperIndexCreationAndDrop(t *testing.T) {
	gk := New(true)

	badIndex := "CREATE INDEX idx_orders_customer ON orders(customer_id);"
	hazards := gk.Inspect(badIndex)
	if len(hazards) == 0 {
		t.Fatalf("expected hazard for non-concurrent index creation")
	}
	block, h := gk.ShouldBlock(hazards)
	if !block || h.Type != HazardNonConcurrentIndex {
		t.Fatalf("expected block on non-concurrent index, got block=%v type=%s", block, h.Type)
	}

	goodIndex := "CREATE INDEX CONCURRENTLY idx_orders_customer ON orders(customer_id);"
	goodHazards := gk.Inspect(goodIndex)
	if len(goodHazards) != 0 {
		t.Fatalf("expected 0 hazards for CONCURRENTLY index creation, got %+v", goodHazards)
	}

	// Non-concurrent DROP INDEX produces WARNING (not blocked by default ERROR threshold)
	dropHazards := gk.Inspect("DROP INDEX idx_orders_customer;")
	if len(dropHazards) != 1 || dropHazards[0].Type != HazardNonConcurrentDrop {
		t.Fatalf("expected HazardNonConcurrentDrop, got %+v", dropHazards)
	}
	if block, _ := gk.ShouldBlock(dropHazards); block {
		t.Fatalf("expected WARNING severity not to block with default ERROR threshold")
	}

	// With BlockSeverity = WARNING, DROP INDEX without CONCURRENTLY MUST block
	strictWarn := NewWithPolicy(Policy{StrictMode: true, BlockSeverity: SeverityWarning})
	if block, _ := strictWarn.ShouldBlock(dropHazards); !block {
		t.Fatalf("expected WARNING severity to block when BlockSeverity=WARNING")
	}

	if h := gk.Inspect("DROP INDEX CONCURRENTLY IF EXISTS idx_orders_customer;"); len(h) != 0 {
		t.Fatalf("expected 0 hazards for DROP INDEX CONCURRENTLY, got %+v", h)
	}
}

func TestGatekeeperUnqualifiedMutationAndTautologies(t *testing.T) {
	gk := New(true)

	blockedCases := []struct {
		name string
		sql  string
	}{
		{"plain_update", "UPDATE accounts SET balance = 0;"},
		{"aliased_update", "UPDATE public.accounts AS a SET balance = 0;"},
		{"only_update", "UPDATE ONLY accounts a SET balance = 0;"},
		{"subquery_where_only", "UPDATE accounts SET rate = (SELECT r FROM rates WHERE active = true);"},
		{"multi_stmt_bypass", "UPDATE accounts SET balance = 0; SELECT * FROM users WHERE id = 1;"},
		{"plain_delete", "DELETE FROM audit_logs;"},
		{"delete_returning_no_where", "DELETE FROM audit_logs RETURNING id;"},
		{"where_true", "DELETE FROM audit_logs WHERE TRUE;"},
		{"where_not_false", "DELETE FROM audit_logs WHERE NOT FALSE;"},
		{"where_1_eq_1", "UPDATE accounts SET balance = 0 WHERE 1 = 1;"},
		{"where_paren_1_eq_1", "DELETE FROM audit_logs WHERE ((1 = 1));"},
		{"where_str_eq_str", "DELETE FROM audit_logs WHERE 'a' = 'a';"},
		{"where_or_tautology", "DELETE FROM audit_logs WHERE user_id = 42 OR 1 = 1;"},
		{"where_or_true", "UPDATE accounts SET balance = 0 WHERE id = $1 OR TRUE;"},
		{"where_and_all_tautology", "DELETE FROM audit_logs WHERE 1 = 1 AND TRUE;"},
		{"writable_cte_unqualified", "WITH wiped AS (DELETE FROM sessions RETURNING *) SELECT count(*) FROM wiped;"},
	}

	for _, tc := range blockedCases {
		t.Run("block_"+tc.name, func(t *testing.T) {
			hazards := gk.Inspect(tc.sql)
			if len(hazards) == 0 {
				t.Fatalf("expected UNQUALIFIED_BULK_MUTATION hazard for %q, got none", tc.sql)
			}
			block, h := gk.ShouldBlock(hazards)
			if !block || h.Type != HazardUnqualifiedMutation {
				t.Fatalf("expected block with UNQUALIFIED_BULK_MUTATION for %q, got block=%v type=%s", tc.sql, block, h.Type)
			}
		})
	}

	allowedCases := []struct {
		name string
		sql  string
	}{
		{"qualified_update", "UPDATE accounts SET balance = 0 WHERE status = 'closed';"},
		{"qualified_delete", "DELETE FROM audit_logs WHERE created_at < now() - interval '90 days';"},
		{"orm_builder_1eq1_and", "UPDATE accounts SET balance = 0 WHERE 1 = 1 AND id = $1;"},
		{"cte_with_qualified_delete", "WITH stale AS (SELECT id FROM sessions WHERE expired = true) DELETE FROM sessions WHERE id IN (SELECT id FROM stale);"},
		{"contradiction_where", "DELETE FROM audit_logs WHERE 1 = 2;"},
	}

	for _, tc := range allowedCases {
		t.Run("allow_"+tc.name, func(t *testing.T) {
			hazards := gk.Inspect(tc.sql)
			if len(hazards) != 0 {
				t.Fatalf("expected 0 hazards for %q, got %+v", tc.sql, hazards)
			}
		})
	}
}

func TestGatekeeperVacuumFullAndOptions(t *testing.T) {
	gk := New(true)

	for _, sql := range []string{
		"VACUUM FULL events;",
		"VACUUM (FULL, ANALYZE) events;",
		"VACUUM (VERBOSE, FULL true) events;",
	} {
		hazards := gk.Inspect(sql)
		if len(hazards) == 0 {
			t.Fatalf("expected VACUUM_FULL hazard for %q", sql)
		}
		block, h := gk.ShouldBlock(hazards)
		if !block || h.Type != HazardVacuumFull {
			t.Fatalf("expected block on VACUUM_FULL for %q, got block=%v type=%s", sql, block, h.Type)
		}
	}

	for _, sql := range []string{
		"VACUUM ANALYZE events;",
		"VACUUM (FULL false, ANALYZE true) events;",
		"VACUUM (FULL off) events;",
	} {
		if hazards := gk.Inspect(sql); len(hazards) != 0 {
			t.Fatalf("expected 0 hazards for %q, got %+v", sql, hazards)
		}
	}
}

func TestGatekeeperTableRewriteAndDestructiveDDL(t *testing.T) {
	gk := New(true)

	// ALTER COLUMN TYPE triggers TABLE_REWRITE_DDL even when lock_timeout is set
	hType := gk.Inspect("SET LOCAL lock_timeout = '2s'; ALTER TABLE payments ALTER COLUMN amount TYPE NUMERIC(14,2);")
	if len(hType) != 1 || hType[0].Type != HazardTableRewriteDDL {
		t.Fatalf("expected TABLE_REWRITE_DDL for ALTER COLUMN TYPE, got %+v", hType)
	}

	// SET DATA TYPE variant
	hSetDataType := gk.Inspect("SET LOCAL lock_timeout = '2s'; ALTER TABLE payments ALTER amount SET DATA TYPE BIGINT;")
	if len(hSetDataType) != 1 || hSetDataType[0].Type != HazardTableRewriteDDL {
		t.Fatalf("expected TABLE_REWRITE_DDL for SET DATA TYPE, got %+v", hSetDataType)
	}

	// Volatile DEFAULT triggers TABLE_REWRITE_DDL
	hVolatile := gk.Inspect("SET LOCAL lock_timeout = '2s'; ALTER TABLE payments ADD COLUMN token UUID DEFAULT gen_random_uuid() NOT NULL;")
	if len(hVolatile) != 1 || hVolatile[0].Type != HazardTableRewriteDDL {
		t.Fatalf("expected TABLE_REWRITE_DDL for volatile default, got %+v", hVolatile)
	}

	// Nested volatile call inside DEFAULT expression
	hNested := gk.Inspect("SET LOCAL lock_timeout = '2s'; ALTER TABLE payments ADD COLUMN hash TEXT DEFAULT md5(random()::text);")
	if len(hNested) != 1 || hNested[0].Type != HazardTableRewriteDDL {
		t.Fatalf("expected TABLE_REWRITE_DDL for nested volatile default, got %+v", hNested)
	}

	// PG 11+ non-volatile constant or STABLE now() default is safe when lock_timeout is set
	if h := gk.Inspect("SET LOCAL lock_timeout = '2s'; ALTER TABLE payments ADD COLUMN created_at TIMESTAMPTZ DEFAULT now(), ADD COLUMN status TEXT DEFAULT 'new';"); len(h) != 0 {
		t.Fatalf("expected 0 hazards for PG 11+ safe defaults, got %+v", h)
	}

	// DROP DATABASE & DROP SCHEMA CASCADE
	hDropDB := gk.Inspect("DROP DATABASE production;")
	if len(hDropDB) != 1 || hDropDB[0].Type != HazardDropDatabaseOrSchema || hDropDB[0].SQLState != "42501" {
		t.Fatalf("expected DROP_DATABASE_OR_SCHEMA for DROP DATABASE, got %+v", hDropDB)
	}
	if hDropDB[0].WireSeverity() != "ERROR" {
		t.Fatalf("expected wire-safe ERROR severity for PANIC hazard, got %s", hDropDB[0].WireSeverity())
	}

	hDropSchema := gk.Inspect("DROP SCHEMA public CASCADE;")
	if len(hDropSchema) != 1 || hDropSchema[0].Type != HazardDropDatabaseOrSchema {
		t.Fatalf("expected DROP_DATABASE_OR_SCHEMA for DROP SCHEMA CASCADE, got %+v", hDropSchema)
	}
	if h := gk.Inspect("DROP SCHEMA empty_scratch RESTRICT;"); len(h) != 0 {
		t.Fatalf("expected 0 hazards for DROP SCHEMA RESTRICT, got %+v", h)
	}

	// LOCK TABLE (blocking vs NOWAIT) and REINDEX (blocking vs CONCURRENTLY)
	if h := gk.Inspect("LOCK TABLE ledger IN ACCESS EXCLUSIVE MODE;"); len(h) != 1 || h[0].Type != HazardTableLockDDL {
		t.Fatalf("expected TABLE_LOCK_DDL for LOCK TABLE without NOWAIT/lock_timeout, got %+v", h)
	}
	if h := gk.Inspect("LOCK TABLE ledger IN SHARE MODE NOWAIT;"); len(h) != 0 {
		t.Fatalf("expected 0 hazards for LOCK TABLE ... NOWAIT, got %+v", h)
	}
	if h := gk.Inspect("REINDEX TABLE orders;"); len(h) != 1 || h[0].Type != HazardTableLockDDL {
		t.Fatalf("expected TABLE_LOCK_DDL for non-concurrent REINDEX without lock_timeout, got %+v", h)
	}
	if h := gk.Inspect("REINDEX TABLE CONCURRENTLY orders;"); len(h) != 0 {
		t.Fatalf("expected 0 hazards for REINDEX TABLE CONCURRENTLY, got %+v", h)
	}
}

func TestLexerCommentsAndLiteralsZeroFalsePositives(t *testing.T) {
	gk := New(true)

	safeQueries := []string{
		"-- ALTER TABLE users DROP COLUMN id;\nSELECT 1;",
		"/* DELETE FROM accounts; /* nested DROP TABLE users; */ VACUUM FULL; */\nSELECT 1;",
		"SELECT 'DROP TABLE users; DELETE FROM accounts; VACUUM FULL;' AS note;",
		"SELECT E'don\\'t DROP TABLE users;' AS msg;",
		"SELECT $$ALTER TABLE users ADD COLUMN x int; DELETE FROM orders;$$ AS ddl_sample;",
		"SELECT $tag$DROP DATABASE prod; VACUUM FULL;$tag$ AS quoted;",
		`SELECT "DROP TABLE" FROM "ALTER TABLE" WHERE id = 1;`,
	}

	for _, sql := range safeQueries {
		if h := gk.Inspect(sql); len(h) != 0 {
			t.Fatalf("false positive on %q: %+v", sql, h)
		}
	}
}

func TestSessionLockTimeoutAndZeroBypassPrevention(t *testing.T) {
	gk := NewWithPolicy(Policy{
		StrictMode:     true,
		MaxLockTimeout: "5s",
	})

	// Zero lock_timeout bypass attempt MUST be caught
	zeroBypass := "SET LOCAL lock_timeout = '0'; ALTER TABLE users ADD COLUMN x INT;"
	hz := gk.Inspect(zeroBypass)
	if len(hz) != 1 || hz[0].Type != HazardLockTimeoutDisabled {
		t.Fatalf("expected LOCK_TIMEOUT_DISABLED on lock_timeout='0' bypass, got %+v", hz)
	}

	// Exceeding MaxLockTimeout MUST be caught
	excess := "SET LOCAL lock_timeout = '30s'; ALTER TABLE users ADD COLUMN x INT;"
	he := gk.Inspect(excess)
	if len(he) == 0 || he[0].Type != HazardLockTimeoutExceeded {
		t.Fatalf("expected LOCK_TIMEOUT_EXCEEDED, got %+v", he)
	}

	// Session state propagation across separate queries
	sess := NewSessionState()
	sess.ApplySQL("BEGIN;")
	sess.ApplySQL("SET LOCAL lock_timeout = '2s';")
	if h := gk.InspectWithSession("ALTER TABLE users ADD COLUMN nick TEXT;", sess); len(h) != 0 {
		t.Fatalf("expected session local lock_timeout to satisfy DDL, got %+v", h)
	}
	// After COMMIT, local lock_timeout MUST expire
	sess.ApplySQL("COMMIT;")
	if h := gk.InspectWithSession("ALTER TABLE users ADD COLUMN bio TEXT;", sess); len(h) != 1 || h[0].Type != HazardTableLockDDL {
		t.Fatalf("expected local lock_timeout to expire after COMMIT, got %+v", h)
	}

	// Session-level SET via set_config persists across transactions until RESET
	sess.ApplySQL("SELECT set_config('lock_timeout', '3s', false);")
	if h := gk.InspectWithSession("ALTER TABLE users ADD COLUMN bio TEXT;", sess); len(h) != 0 {
		t.Fatalf("expected set_config session lock_timeout to apply, got %+v", h)
	}
	sess.ApplySQL("RESET lock_timeout;")
	if h := gk.InspectWithSession("ALTER TABLE users ADD COLUMN bio TEXT;", sess); len(h) != 1 || h[0].Type != HazardTableLockDDL {
		t.Fatalf("expected RESET lock_timeout to clear timeout, got %+v", h)
	}

	// Legitimate post-migration reset to 0 after safe DDL has zero hazards
	legitMigration := "SET lock_timeout = '2s'; ALTER TABLE users ADD COLUMN x INT; SET lock_timeout = '0';"
	if h := gk.Inspect(legitMigration); len(h) != 0 {
		t.Fatalf("expected 0 hazards on safe migration with trailing reset, got %+v", h)
	}
}

func TestParsePGDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"2s", 2 * time.Second, true},
		{"500ms", 500 * time.Millisecond, true},
		{"500 ms", 500 * time.Millisecond, true},
		{"2000", 2 * time.Second, true}, // bare int is ms in PG
		{"1min", time.Minute, true},
		{"0", 0, true},
		{"DEFAULT", 0, true},
		{"100us", 100 * time.Microsecond, true},
		{"invalid", 0, false},
		{"-5s", 0, false},
	}
	for _, tc := range cases {
		got, ok := ParsePGDuration(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("ParsePGDuration(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestPolicyAllowlistDisabledRulesAndJSONReport(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	rawPolicy := `{
		"strict_mode": true,
		"block_severity": "ERROR",
		"max_lock_timeout": "5s",
		"disabled_rules": ["NON_CONCURRENT_DROP_INDEX"],
		"allowlisted_tables": ["scratch_imports", "staging.temp_events"]
	}`
	if err := os.WriteFile(policyPath, []byte(rawPolicy), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	pol, err := LoadPolicyFile(policyPath)
	if err != nil {
		t.Fatalf("LoadPolicyFile failed: %v", err)
	}
	gk := NewWithPolicy(pol)

	// Allowlisted tables bypass table-scoped hazards
	if h := gk.Inspect("TRUNCATE TABLE public.scratch_imports;"); len(h) != 0 {
		t.Fatalf("expected allowlisted unqualified table to pass, got %+v", h)
	}
	if h := gk.Inspect("DELETE FROM staging.temp_events;"); len(h) != 0 {
		t.Fatalf("expected allowlisted schema.table to pass, got %+v", h)
	}
	// Disabled rule skipped
	if h := gk.Inspect("DROP INDEX idx_old;"); len(h) != 0 {
		t.Fatalf("expected disabled rule to be skipped, got %+v", h)
	}

	// Structured JSON report with line numbers across a multi-line migration
	migration := strings.Join([]string{
		"-- Migration 0042",
		"SELECT 1;",
		"ALTER TABLE users ADD COLUMN legacy TEXT;",
		"DELETE FROM sessions;",
	}, "\n")
	report := gk.BuildReport(migration, "0042.sql")
	if report.Clean || !report.Blocked || report.StatementCount != 3 || report.HazardCount != 2 {
		t.Fatalf("unexpected InspectReport: %+v", report)
	}
	if report.Hazards[0].Line != 3 || report.Hazards[1].Line != 4 {
		t.Fatalf("unexpected hazard line numbers: %+v", report.Hazards)
	}
	encoded, err := FormatReportJSON(report)
	if err != nil {
		t.Fatalf("FormatReportJSON failed: %v", err)
	}
	var decoded InspectReport
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal report JSON: %v", err)
	}
	if decoded.Source != "0042.sql" || len(decoded.Hazards) != 2 {
		t.Fatalf("round-trip JSON mismatch: %+v", decoded)
	}
}
