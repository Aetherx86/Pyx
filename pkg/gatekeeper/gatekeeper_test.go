package gatekeeper

import (
	"testing"
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
		t.Fatalf("expected 0 hazards for safe DDL with lock_timeout, got %d", len(safeHazards))
	}
}

func TestGatekeeperIndexCreation(t *testing.T) {
	gk := New(true)

	badIndex := "CREATE INDEX idx_orders_customer ON orders(customer_id);"
	hazards := gk.Inspect(badIndex)
	if len(hazards) == 0 {
		t.Fatalf("expected hazard for non-concurrent index creation")
	}
	block, h := gk.ShouldBlock(hazards)
	if !block || h.Type != HazardNonConcurrentIndex {
		t.Fatalf("expected block on non-concurrent index")
	}

	goodIndex := "CREATE INDEX CONCURRENTLY idx_orders_customer ON orders(customer_id);"
	goodHazards := gk.Inspect(goodIndex)
	if len(goodHazards) != 0 {
		t.Fatalf("expected 0 hazards for CONCURRENTLY index creation")
	}
}

func TestGatekeeperUnqualifiedMutation(t *testing.T) {
	gk := New(true)

	badUpdate := "UPDATE accounts SET balance = 0;"
	hazards := gk.Inspect(badUpdate)
	if len(hazards) == 0 {
		t.Fatalf("expected hazard for unqualified UPDATE")
	}
	block, _ := gk.ShouldBlock(hazards)
	if !block {
		t.Fatalf("expected block on unqualified UPDATE")
	}

	goodUpdate := "UPDATE accounts SET balance = 0 WHERE status = 'closed';"
	goodHazards := gk.Inspect(goodUpdate)
	if len(goodHazards) != 0 {
		t.Fatalf("expected 0 hazards for qualified UPDATE with WHERE clause")
	}

	badDelete := "DELETE FROM audit_logs;"
	delHazards := gk.Inspect(badDelete)
	if len(delHazards) == 0 {
		t.Fatalf("expected hazard for unqualified DELETE")
	}
}

func TestGatekeeperVacuumFull(t *testing.T) {
	gk := New(true)
	hazards := gk.Inspect("VACUUM FULL events;")
	if len(hazards) == 0 {
		t.Fatalf("expected hazard on VACUUM FULL")
	}
	block, _ := gk.ShouldBlock(hazards)
	if !block {
		t.Fatalf("expected block on VACUUM FULL")
	}
}
