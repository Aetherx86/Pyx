package gatekeeper

import (
	"fmt"
	"regexp"
	"strings"
)

type Severity string

const (
	SeverityNotice   Severity = "NOTICE"
	SeverityWarning  Severity = "WARNING"
	SeverityHigh     Severity = "ERROR"
	SeverityCritical Severity = "PANIC"
)

type HazardType string

const (
	HazardTableLockDDL         HazardType = "TABLE_LOCK_DDL"
	HazardNonConcurrentIndex   HazardType = "NON_CONCURRENT_INDEX"
	HazardUnqualifiedMutation  HazardType = "UNQUALIFIED_BULK_MUTATION"
	HazardVacuumFull           HazardType = "VACUUM_FULL"
	HazardNonConcurrentDrop    HazardType = "NON_CONCURRENT_DROP_INDEX"
)

// Hazard describes an intercepted database anti-pattern.
type Hazard struct {
	Type     HazardType
	Severity Severity
	SQLState string // PostgreSQL standard 5-character SQLSTATE
	Message  string
	Detail   string
}

type Gatekeeper struct {
	modeStrict bool
}

func New(strict bool) *Gatekeeper {
	return &Gatekeeper{
		modeStrict: strict,
	}
}

var (
	reAlterTable = regexp.MustCompile(`(?i)\bALTER\s+TABLE\b`)
	reDropTable  = regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`)
	reTruncate   = regexp.MustCompile(`(?i)\bTRUNCATE\b`)
	reVacuumFull = regexp.MustCompile(`(?i)\bVACUUM\s+FULL\b`)

	reCreateIndex    = regexp.MustCompile(`(?i)\bCREATE\s+(?:UNIQUE\s+)?INDEX\b`)
	reConcurrently   = regexp.MustCompile(`(?i)\bCONCURRENTLY\b`)
	reDropIndex      = regexp.MustCompile(`(?i)\bDROP\s+INDEX\b`)

	reUpdate = regexp.MustCompile(`(?i)\bUPDATE\s+([a-zA-Z0-9_."]+)\s+SET\b`)
	reDelete = regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+([a-zA-Z0-9_."]+)\b`)
	reWhere  = regexp.MustCompile(`(?i)\bWHERE\b`)

	reLockTimeout = regexp.MustCompile(`(?i)\bSET\s+(?:LOCAL\s+)?lock_timeout\b`)
)

// Inspect evaluates a raw SQL statement and returns any identified hazardous patterns.
func (g *Gatekeeper) Inspect(sql string) []Hazard {
	var hazards []Hazard
	clean := strings.TrimSpace(sql)
	if clean == "" {
		return nil
	}

	hasLockTimeout := reLockTimeout.MatchString(clean)

	// 1. Table-Locking DDL Hazard
	if (reAlterTable.MatchString(clean) || reDropTable.MatchString(clean) || reTruncate.MatchString(clean)) && !hasLockTimeout {
		hazards = append(hazards, Hazard{
			Type:     HazardTableLockDDL,
			Severity: SeverityHigh,
			SQLState: "55P03", // lock_not_available
			Message:  "Pyx Gatekeeper: Table-locking DDL operation detected without lock_timeout",
			Detail:   "DDL queries requiring ACCESS EXCLUSIVE table locks must be preceded by 'SET LOCAL lock_timeout' to prevent connection queue starvation.",
		})
	}

	// 2. Non-concurrent Index Creation
	if reCreateIndex.MatchString(clean) && !reConcurrently.MatchString(clean) {
		hazards = append(hazards, Hazard{
			Type:     HazardNonConcurrentIndex,
			Severity: SeverityHigh,
			SQLState: "54000", // program_limit_exceeded
			Message:  "Pyx Gatekeeper: Non-concurrent index creation blocked",
			Detail:   "Creating indexes without CONCURRENTLY takes a SHARE table lock, blocking write operations during index population. Use CREATE INDEX CONCURRENTLY.",
		})
	}

	// 3. Non-concurrent Index Drop
	if reDropIndex.MatchString(clean) && !reConcurrently.MatchString(clean) {
		hazards = append(hazards, Hazard{
			Type:     HazardNonConcurrentDrop,
			Severity: SeverityWarning,
			SQLState: "54000",
			Message:  "Pyx Gatekeeper: Non-concurrent index drop detected",
			Detail:   "Dropping indexes without CONCURRENTLY acquires an ACCESS EXCLUSIVE lock on the index and table. Use DROP INDEX CONCURRENTLY.",
		})
	}

	// 4. VACUUM FULL Hazard
	if reVacuumFull.MatchString(clean) {
		hazards = append(hazards, Hazard{
			Type:     HazardVacuumFull,
			Severity: SeverityHigh,
			SQLState: "55P03",
			Message:  "Pyx Gatekeeper: VACUUM FULL execution prohibited",
			Detail:   "VACUUM FULL locks the entire table against both reads and writes until rewrites finish. Use pg_repack or incremental vacuum.",
		})
	}

	// 5. Unqualified Bulk Mutation Hazard (UPDATE or DELETE with no WHERE clause)
	if (reUpdate.MatchString(clean) || reDelete.MatchString(clean)) && !reWhere.MatchString(clean) {
		hazards = append(hazards, Hazard{
			Type:     HazardUnqualifiedMutation,
			Severity: SeverityHigh,
			SQLState: "54000",
			Message:  "Pyx Gatekeeper: Unqualified bulk table mutation prohibited",
			Detail:   "UPDATE or DELETE statement detected with zero WHERE qualification, which would mutate or delete all records in the table.",
		})
	}

	return hazards
}

// ShouldBlock determines if the detected hazards should cause an immediate wire-level rejection.
func (g *Gatekeeper) ShouldBlock(hazards []Hazard) (bool, Hazard) {
	if !g.modeStrict || len(hazards) == 0 {
		return false, Hazard{}
	}
	for _, h := range hazards {
		if h.Severity == SeverityHigh || h.Severity == SeverityCritical {
			return true, h
		}
	}
	return false, Hazard{}
}

// String outputs a human-readable diagnosis of hazards.
func FormatHazards(hazards []Hazard) string {
	if len(hazards) == 0 {
		return "clean: no database wire hazards detected"
	}
	var sb strings.Builder
	for i, h := range hazards {
		sb.WriteString(fmt.Sprintf("[%d] %s (Severity: %s, SQLState: %s): %s\n    Detail: %s\n",
			i+1, h.Type, h.Severity, h.SQLState, h.Message, h.Detail))
	}
	return sb.String()
}
