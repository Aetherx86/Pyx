package gatekeeper

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Severity string

const (
	SeverityNotice   Severity = "NOTICE"
	SeverityWarning  Severity = "WARNING"
	SeverityHigh     Severity = "ERROR"
	SeverityCritical Severity = "PANIC"
)

func severityRank(s Severity) int {
	switch Severity(strings.ToUpper(string(s))) {
	case SeverityNotice:
		return 1
	case SeverityWarning:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 3
	}
}

type HazardType string

const (
	HazardTableLockDDL         HazardType = "TABLE_LOCK_DDL"
	HazardNonConcurrentIndex   HazardType = "NON_CONCURRENT_INDEX"
	HazardUnqualifiedMutation  HazardType = "UNQUALIFIED_BULK_MUTATION"
	HazardVacuumFull           HazardType = "VACUUM_FULL"
	HazardNonConcurrentDrop    HazardType = "NON_CONCURRENT_DROP_INDEX"
	HazardTableRewriteDDL      HazardType = "TABLE_REWRITE_DDL"
	HazardDropDatabaseOrSchema HazardType = "DROP_DATABASE_OR_SCHEMA"
	HazardLockTimeoutDisabled  HazardType = "LOCK_TIMEOUT_DISABLED"
	HazardLockTimeoutExceeded  HazardType = "LOCK_TIMEOUT_EXCEEDED"
)

// Hazard describes an intercepted database anti-pattern.
type Hazard struct {
	Type           HazardType `json:"type"`
	Severity       Severity   `json:"severity"`
	SQLState       string     `json:"sqlstate"` // PostgreSQL standard 5-character SQLSTATE
	Message        string     `json:"message"`
	Detail         string     `json:"detail"`
	Remediation    string     `json:"remediation,omitempty"`
	Table          string     `json:"table,omitempty"`
	StatementIndex int        `json:"statement_index,omitempty"`
	Line           int        `json:"line,omitempty"`
}

// WireSeverity maps internal hazard severity to a PostgreSQL wire-safe ErrorResponse
// severity level so non-fatal policy rejections never cause clients to drop connections.
func (h Hazard) WireSeverity() string {
	switch h.Severity {
	case SeverityNotice:
		return "NOTICE"
	case SeverityWarning:
		return "WARNING"
	default:
		return "ERROR"
	}
}

// Policy defines configurable SQL enforcement behavior for Gatekeeper.
type Policy struct {
	StrictMode        bool         `json:"strict_mode"`
	BlockSeverity     Severity     `json:"block_severity,omitempty"`
	MaxLockTimeout    string       `json:"max_lock_timeout,omitempty"`
	DisabledRules     []HazardType `json:"disabled_rules,omitempty"`
	AllowlistedTables []string     `json:"allowlisted_tables,omitempty"`
}

// DefaultPolicy returns the standard production policy for strict or audit mode.
func DefaultPolicy(strict bool) Policy {
	return Policy{
		StrictMode:    strict,
		BlockSeverity: SeverityHigh,
	}
}

// LoadPolicyFile reads and validates a JSON Policy configuration file from disk.
func LoadPolicyFile(path string) (Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy file: %w", err)
	}
	p := DefaultPolicy(true)
	if err := json.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse policy JSON: %w", err)
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Validate checks Policy fields for consistency and valid timeout syntax.
func (p Policy) Validate() error {
	if p.BlockSeverity != "" {
		switch Severity(strings.ToUpper(string(p.BlockSeverity))) {
		case SeverityNotice, SeverityWarning, SeverityHigh, SeverityCritical:
		default:
			return fmt.Errorf("invalid block_severity %q", p.BlockSeverity)
		}
	}
	if p.MaxLockTimeout != "" {
		d, ok := ParsePGDuration(p.MaxLockTimeout)
		if !ok || d <= 0 {
			return fmt.Errorf("invalid max_lock_timeout %q: must be a positive PostgreSQL duration (e.g. '5s', '500ms')", p.MaxLockTimeout)
		}
	}
	return nil
}

// InspectReport provides a structured summary suitable for CLI or JSON output.
type InspectReport struct {
	Clean          bool     `json:"clean"`
	Blocked        bool     `json:"blocked"`
	Mode           string   `json:"mode"`
	Source         string   `json:"source,omitempty"`
	StatementCount int      `json:"statement_count"`
	HazardCount    int      `json:"hazard_count"`
	Hazards        []Hazard `json:"hazards"`
}

// Gatekeeper inspects PostgreSQL SQL statements against configured safety rules.
type Gatekeeper struct {
	modeStrict        bool
	policy            Policy
	blockRank         int
	maxLockTimeout    time.Duration
	disabledRules     map[HazardType]struct{}
	allowlistedTables map[string]struct{}
}

// New creates a Gatekeeper using the default policy for strict or audit mode.
func New(strict bool) *Gatekeeper {
	return NewWithPolicy(DefaultPolicy(strict))
}

// NewWithPolicy constructs a Gatekeeper with explicit policy configuration.
func NewWithPolicy(p Policy) *Gatekeeper {
	if p.BlockSeverity == "" {
		p.BlockSeverity = SeverityHigh
	}
	disabled := make(map[HazardType]struct{}, len(p.DisabledRules))
	for _, r := range p.DisabledRules {
		disabled[r] = struct{}{}
	}
	allowed := make(map[string]struct{}, len(p.AllowlistedTables))
	for _, tbl := range p.AllowlistedTables {
		norm := strings.ToLower(strings.TrimSpace(tbl))
		if norm != "" {
			allowed[norm] = struct{}{}
		}
	}
	var maxLT time.Duration
	if p.MaxLockTimeout != "" {
		if d, ok := ParsePGDuration(p.MaxLockTimeout); ok && d > 0 {
			maxLT = d
		}
	}
	return &Gatekeeper{
		modeStrict:        p.StrictMode,
		policy:            p,
		blockRank:         severityRank(p.BlockSeverity),
		maxLockTimeout:    maxLT,
		disabledRules:     disabled,
		allowlistedTables: allowed,
	}
}

// Policy returns a copy of the active gatekeeper policy.
func (g *Gatekeeper) Policy() Policy {
	return g.policy
}

// Inspect evaluates a raw SQL string in a fresh stateless session and returns all detected hazards.
func (g *Gatekeeper) Inspect(sql string) []Hazard {
	return g.InspectWithSession(sql, nil)
}

// InspectWithSession evaluates sql against an existing connection SessionState without
// mutating the caller's SessionState (callers should call session.ApplySQL only when
// the query is allowed and forwarded to PostgreSQL).
func (g *Gatekeeper) InspectWithSession(sql string, session *SessionState) []Hazard {
	stmts := LexStatements(sql)
	if len(stmts) == 0 {
		return nil
	}

	working := session.Clone()
	var hazards []Hazard
	for _, stmt := range stmts {
		hazards = append(hazards, g.inspectStatement(stmt, working)...)
	}
	return hazards
}

// BuildReport evaluates sql and returns a structured InspectReport.
func (g *Gatekeeper) BuildReport(sql, source string) InspectReport {
	stmts := LexStatements(sql)
	working := NewSessionState()
	hazards := make([]Hazard, 0)
	for _, stmt := range stmts {
		hazards = append(hazards, g.inspectStatement(stmt, working)...)
	}
	blocked, _ := g.ShouldBlock(hazards)
	mode := "audit"
	if g.modeStrict {
		mode = "strict"
	}
	return InspectReport{
		Clean:          len(hazards) == 0,
		Blocked:        blocked,
		Mode:           mode,
		Source:         source,
		StatementCount: len(stmts),
		HazardCount:    len(hazards),
		Hazards:        hazards,
	}
}

// FormatReportJSON encodes an InspectReport as indented JSON.
func FormatReportJSON(report InspectReport) ([]byte, error) {
	if report.Hazards == nil {
		report.Hazards = []Hazard{}
	}
	return json.MarshalIndent(report, "", "  ")
}

// ShouldBlock determines if the detected hazards should cause an immediate wire-level rejection.
func (g *Gatekeeper) ShouldBlock(hazards []Hazard) (bool, Hazard) {
	if !g.modeStrict || len(hazards) == 0 {
		return false, Hazard{}
	}
	var worst Hazard
	found := false
	for _, h := range hazards {
		if severityRank(h.Severity) >= g.blockRank {
			if !found || severityRank(h.Severity) > severityRank(worst.Severity) {
				worst = h
				found = true
			}
		}
	}
	return found, worst
}

// FormatHazards outputs a human-readable diagnosis of hazards.
func FormatHazards(hazards []Hazard) string {
	if len(hazards) == 0 {
		return "clean: no database wire hazards detected"
	}
	var sb strings.Builder
	for i, h := range hazards {
		loc := ""
		if h.Line > 0 {
			loc = fmt.Sprintf(" [line %d, stmt %d]", h.Line, h.StatementIndex)
		}
		sb.WriteString(fmt.Sprintf("[%d] %s%s (Severity: %s, SQLState: %s): %s\n    Detail: %s\n",
			i+1, h.Type, loc, h.Severity, h.SQLState, h.Message, h.Detail))
		if h.Remediation != "" {
			sb.WriteString(fmt.Sprintf("    Remediation: %s\n", h.Remediation))
		}
	}
	return sb.String()
}

func (g *Gatekeeper) isRuleDisabled(t HazardType) bool {
	_, ok := g.disabledRules[t]
	return ok
}

func (g *Gatekeeper) isTableAllowlisted(table string) bool {
	if table == "" || len(g.allowlistedTables) == 0 {
		return false
	}
	norm := strings.ToLower(table)
	if _, ok := g.allowlistedTables[norm]; ok {
		return true
	}
	if dot := strings.LastIndexByte(norm, '.'); dot >= 0 && dot+1 < len(norm) {
		if _, ok := g.allowlistedTables[norm[dot+1:]]; ok {
			return true
		}
	}
	return false
}

func (g *Gatekeeper) allTablesAllowlisted(tables []string) bool {
	if len(tables) == 0 || len(g.allowlistedTables) == 0 {
		return false
	}
	for _, tbl := range tables {
		if !g.isTableAllowlisted(tbl) {
			return false
		}
	}
	return true
}

func (g *Gatekeeper) addHazard(out *[]Hazard, h Hazard, stmt Statement) {
	if g.isRuleDisabled(h.Type) {
		return
	}
	h.StatementIndex = stmt.Index
	h.Line = stmt.Line
	*out = append(*out, h)
}

func (g *Gatekeeper) inspectStatement(stmt Statement, session *SessionState) []Hazard {
	tokens := stmt.Tokens
	if len(tokens) == 0 {
		return nil
	}

	var hazards []Hazard

	// Apply state transitions first (BEGIN, COMMIT, ROLLBACK, SET lock_timeout, RESET, set_config).
	prevTimeout, prevConfigured := session.EffectiveLockTimeout()
	session.ApplyTokens(tokens)
	curTimeout, curConfigured := session.EffectiveLockTimeout()
	// Check if a SET lock_timeout explicitly exceeded Policy.MaxLockTimeout.
	if g.maxLockTimeout > 0 && curConfigured && curTimeout > g.maxLockTimeout &&
		(!prevConfigured || curTimeout != prevTimeout) {
		g.addHazard(&hazards, Hazard{
			Type:        HazardLockTimeoutExceeded,
			Severity:    SeverityHigh,
			SQLState:    "55P03",
			Message:     fmt.Sprintf("Pyx Gatekeeper: lock_timeout (%s) exceeds policy maximum (%s)", curTimeout, g.maxLockTimeout),
			Detail:      fmt.Sprintf("Configured lock_timeout of %s exceeds the enforced safety ceiling of %s.", curTimeout, g.maxLockTimeout),
			Remediation: fmt.Sprintf("Set lock_timeout <= %s (e.g. SET LOCAL lock_timeout = '%s';).", g.maxLockTimeout, g.maxLockTimeout),
		}, stmt)
	}

	// Unwrap leading WITH [RECURSIVE] CTEs while also inspecting writable CTE bodies.
	mainTokens := tokens
	if mainTokens[0].Kind == TokWord && mainTokens[0].Upper == "WITH" {
		rest, cteBodies := splitLeadingCTEs(mainTokens)
		for _, body := range cteBodies {
			g.inspectMutation(body, stmt, &hazards)
		}
		if len(rest) == 0 {
			return hazards
		}
		mainTokens = rest
	}

	if mainTokens[0].Kind != TokWord {
		return hazards
	}

	switch mainTokens[0].Upper {
	case "ALTER":
		g.inspectAlter(mainTokens, stmt, session, &hazards)
	case "DROP":
		g.inspectDrop(mainTokens, stmt, session, &hazards)
	case "TRUNCATE":
		g.inspectTruncate(mainTokens, stmt, session, &hazards)
	case "LOCK":
		g.inspectLockTable(mainTokens, stmt, session, &hazards)
	case "CLUSTER":
		g.inspectCluster(mainTokens, stmt, session, &hazards)
	case "REINDEX":
		g.inspectReindex(mainTokens, stmt, session, &hazards)
	case "CREATE":
		g.inspectCreate(mainTokens, stmt, &hazards)
	case "VACUUM":
		g.inspectVacuum(mainTokens, stmt, &hazards)
	case "UPDATE", "DELETE":
		g.inspectMutation(mainTokens, stmt, &hazards)
	}

	return hazards
}

func (g *Gatekeeper) checkLockTimeout(session *SessionState, opName, table string, stmt Statement, out *[]Hazard) {
	dur, configured := session.EffectiveLockTimeout()
	if !configured {
		g.addHazard(out, Hazard{
			Type:        HazardTableLockDDL,
			Severity:    SeverityHigh,
			SQLState:    "55P03",
			Message:     "Pyx Gatekeeper: Table-locking DDL operation detected without lock_timeout",
			Detail:      fmt.Sprintf("%s acquires heavy table locks and must be preceded by 'SET LOCAL lock_timeout' to prevent connection queue starvation.", opName),
			Remediation: "Prepend SET LOCAL lock_timeout = '2s'; before executing locking DDL.",
			Table:       table,
		}, stmt)
		return
	}
	if dur <= 0 {
		g.addHazard(out, Hazard{
			Type:        HazardLockTimeoutDisabled,
			Severity:    SeverityHigh,
			SQLState:    "55P03",
			Message:     "Pyx Gatekeeper: Table-locking DDL executed with lock_timeout disabled (0)",
			Detail:      fmt.Sprintf("%s executed while lock_timeout is set to 0/DEFAULT, allowing unbounded lock wait queues.", opName),
			Remediation: "Configure a positive bounded timeout such as SET LOCAL lock_timeout = '2s';.",
			Table:       table,
		}, stmt)
		return
	}
	if g.maxLockTimeout > 0 && dur > g.maxLockTimeout {
		g.addHazard(out, Hazard{
			Type:        HazardLockTimeoutExceeded,
			Severity:    SeverityHigh,
			SQLState:    "55P03",
			Message:     fmt.Sprintf("Pyx Gatekeeper: Table-locking DDL lock_timeout (%s) exceeds policy limit (%s)", dur, g.maxLockTimeout),
			Detail:      fmt.Sprintf("%s uses lock_timeout=%s which exceeds configured policy limit of %s.", opName, dur, g.maxLockTimeout),
			Remediation: fmt.Sprintf("Reduce lock_timeout to <= %s.", g.maxLockTimeout),
			Table:       table,
		}, stmt)
	}
}

func (g *Gatekeeper) inspectAlter(tokens []Token, stmt Statement, session *SessionState, out *[]Hazard) {
	if len(tokens) < 2 || tokens[1].Kind != TokWord || tokens[1].Upper != "TABLE" {
		return
	}
	i := 2
	// Optional IF EXISTS
	if i+1 < len(tokens) && isWord(tokens[i], "IF") && isWord(tokens[i+1], "EXISTS") {
		i += 2
	}
	// Optional ONLY
	if i < len(tokens) && isWord(tokens[i], "ONLY") {
		i++
	}
	tbl, nextIdx := parseTableName(tokens, i)
	if g.isTableAllowlisted(tbl) {
		return
	}

	g.checkLockTimeout(session, "ALTER TABLE", tbl, stmt, out)

	// Inspect ALTER TABLE actions for full table rewrites under ACCESS EXCLUSIVE lock.
	if nextIdx < len(tokens) {
		g.inspectAlterTableRewrites(tokens[nextIdx:], tbl, stmt, out)
	}
}

var volatileFunctions = map[string]struct{}{
	"RANDOM":             {},
	"CLOCK_TIMESTAMP":    {},
	"TIMEOFDAY":          {},
	"GEN_RANDOM_UUID":    {},
	"UUID_GENERATE_V1":   {},
	"UUID_GENERATE_V1MC": {},
	"UUID_GENERATE_V4":   {},
	"NEXTVAL":            {},
	"TXID_CURRENT":       {},
	"PG_CURRENT_XACT_ID": {},
}

func (g *Gatekeeper) inspectAlterTableRewrites(actions []Token, table string, stmt Statement, out *[]Hazard) {
	// Split top-level comma-separated ALTER TABLE subcommands.
	subcommands := splitTopLevelComma(actions)
	emitted := false
	for _, sub := range subcommands {
		if emitted || len(sub) < 2 {
			continue
		}
		// 1. ALTER [COLUMN] <col> [SET DATA] TYPE ...
		if isWord(sub[0], "ALTER") {
			j := 1
			if j < len(sub) && isWord(sub[j], "COLUMN") {
				j++
			}
			// Skip column identifier
			if j < len(sub) && (sub[j].Kind == TokWord || sub[j].Kind == TokIdent) {
				j++
			}
			isTypeChange := false
			if j < len(sub) && isWord(sub[j], "TYPE") {
				isTypeChange = true
			} else if j+2 < len(sub) && isWord(sub[j], "SET") && isWord(sub[j+1], "DATA") && isWord(sub[j+2], "TYPE") {
				isTypeChange = true
			}
			if isTypeChange {
				g.addHazard(out, Hazard{
					Type:        HazardTableRewriteDDL,
					Severity:    SeverityHigh,
					SQLState:    "55P03",
					Message:     "Pyx Gatekeeper: Full table rewrite DDL (ALTER COLUMN TYPE) detected",
					Detail:      "Changing a column data type via ALTER TABLE ... ALTER COLUMN TYPE triggers an ACCESS EXCLUSIVE table rewrite, blocking all reads and writes until completion.",
					Remediation: "Use expand-and-contract migration: add a new column, backfill in batches, swap references, and drop the old column.",
					Table:       table,
				}, stmt)
				emitted = true
				continue
			}
		}

		// 2. ADD [COLUMN] [IF NOT EXISTS] <col> <type> ... DEFAULT <volatile_fn(...)>
		if isWord(sub[0], "ADD") {
			j := 1
			// Skip table constraints (ADD CONSTRAINT, ADD PRIMARY KEY, ADD UNIQUE, ADD FOREIGN KEY, ADD CHECK, ADD EXCLUDE)
			if j < len(sub) && (isWord(sub[j], "CONSTRAINT") || isWord(sub[j], "PRIMARY") ||
				isWord(sub[j], "UNIQUE") || isWord(sub[j], "FOREIGN") || isWord(sub[j], "CHECK") || isWord(sub[j], "EXCLUDE")) {
				continue
			}
			// Scan for DEFAULT clause at parenDepth 0, then check expression for volatile function calls.
			depth := 0
			for k := j; k < len(sub); k++ {
				switch sub[k].Kind {
				case TokLParen:
					depth++
				case TokRParen:
					if depth > 0 {
						depth--
					}
				}
				if depth == 0 && isWord(sub[k], "DEFAULT") {
					if fn := findVolatileCall(sub[k+1:]); fn != "" {
						g.addHazard(out, Hazard{
							Type:        HazardTableRewriteDDL,
							Severity:    SeverityHigh,
							SQLState:    "55P03",
							Message:     fmt.Sprintf("Pyx Gatekeeper: Full table rewrite DDL (ADD COLUMN with volatile DEFAULT %s()) detected", fn),
							Detail:      fmt.Sprintf("ADD COLUMN with volatile default expression '%s()' forces PostgreSQL to rewrite every existing row under an ACCESS EXCLUSIVE lock.", fn),
							Remediation: "Add the column nullable without a volatile default, set the default for new rows, and backfill existing rows in batches.",
							Table:       table,
						}, stmt)
						emitted = true
					}
					break
				}
			}
		}
	}
}

func findVolatileCall(tokens []Token) string {
	depth := 0
	for i := 0; i < len(tokens); i++ {
		if depth == 0 && tokens[i].Kind == TokWord {
			switch tokens[i].Upper {
			case "NOT", "NULL", "CONSTRAINT", "PRIMARY", "UNIQUE", "CHECK", "REFERENCES", "COLLATE", "GENERATED":
				return ""
			}
		}
		if tokens[i].Kind == TokLParen {
			depth++
			continue
		}
		if tokens[i].Kind == TokRParen {
			if depth > 0 {
				depth--
			}
			continue
		}
		if tokens[i].Kind == TokWord && i+1 < len(tokens) && tokens[i+1].Kind == TokLParen {
			if _, ok := volatileFunctions[tokens[i].Upper]; ok {
				return strings.ToLower(tokens[i].Raw)
			}
		}
	}
	return ""
}

func (g *Gatekeeper) inspectDrop(tokens []Token, stmt Statement, session *SessionState, out *[]Hazard) {
	if len(tokens) < 2 || tokens[1].Kind != TokWord {
		return
	}
	switch tokens[1].Upper {
	case "TABLE":
		i := 2
		if i+1 < len(tokens) && isWord(tokens[i], "IF") && isWord(tokens[i+1], "EXISTS") {
			i += 2
		}
		tables := parseTableList(tokens, i, map[string]bool{"CASCADE": true, "RESTRICT": true})
		if g.allTablesAllowlisted(tables) {
			return
		}
		primary := ""
		if len(tables) > 0 {
			primary = tables[0]
		}
		g.checkLockTimeout(session, "DROP TABLE", primary, stmt, out)

	case "INDEX":
		if !hasTopLevelWord(tokens[2:], "CONCURRENTLY") {
			g.addHazard(out, Hazard{
				Type:        HazardNonConcurrentDrop,
				Severity:    SeverityWarning,
				SQLState:    "54000",
				Message:     "Pyx Gatekeeper: Non-concurrent index drop detected",
				Detail:      "Dropping indexes without CONCURRENTLY acquires an ACCESS EXCLUSIVE lock on the index and table. Use DROP INDEX CONCURRENTLY.",
				Remediation: "Replace DROP INDEX with DROP INDEX CONCURRENTLY.",
			}, stmt)
		}

	case "DATABASE":
		g.addHazard(out, Hazard{
			Type:        HazardDropDatabaseOrSchema,
			Severity:    SeverityCritical,
			SQLState:    "42501",
			Message:     "Pyx Gatekeeper: Destructive DROP DATABASE operation prohibited",
			Detail:      "DROP DATABASE permanently destroys the entire database catalog and all contained data.",
			Remediation: "Execute database decommissioning through controlled administrative runbooks outside application proxy traffic.",
		}, stmt)

	case "SCHEMA":
		if hasTopLevelWord(tokens[2:], "CASCADE") {
			g.addHazard(out, Hazard{
				Type:        HazardDropDatabaseOrSchema,
				Severity:    SeverityCritical,
				SQLState:    "42501",
				Message:     "Pyx Gatekeeper: Destructive DROP SCHEMA ... CASCADE operation prohibited",
				Detail:      "DROP SCHEMA ... CASCADE recursively drops all tables, views, indexes, and functions within the schema.",
				Remediation: "Drop individual objects explicitly or use DROP SCHEMA RESTRICT on an empty schema.",
			}, stmt)
		}
	}
}

func (g *Gatekeeper) inspectTruncate(tokens []Token, stmt Statement, session *SessionState, out *[]Hazard) {
	i := 1
	if i < len(tokens) && isWord(tokens[i], "TABLE") {
		i++
	}
	if i < len(tokens) && isWord(tokens[i], "ONLY") {
		i++
	}
	tables := parseTableList(tokens, i, map[string]bool{
		"RESTART": true, "CONTINUE": true, "IDENTITY": true, "CASCADE": true, "RESTRICT": true,
	})
	if g.allTablesAllowlisted(tables) {
		return
	}
	primary := ""
	if len(tables) > 0 {
		primary = tables[0]
	}
	g.checkLockTimeout(session, "TRUNCATE", primary, stmt, out)
}

func (g *Gatekeeper) inspectLockTable(tokens []Token, stmt Statement, session *SessionState, out *[]Hazard) {
	// LOCK [TABLE] [ONLY] name [, ...] [IN lockmode MODE] [NOWAIT]
	if hasTopLevelWord(tokens[1:], "NOWAIT") {
		return
	}
	i := 1
	if i < len(tokens) && isWord(tokens[i], "TABLE") {
		i++
	}
	if i < len(tokens) && isWord(tokens[i], "ONLY") {
		i++
	}
	tables := parseTableList(tokens, i, map[string]bool{"IN": true, "NOWAIT": true})
	if g.allTablesAllowlisted(tables) {
		return
	}
	primary := ""
	if len(tables) > 0 {
		primary = tables[0]
	}
	g.checkLockTimeout(session, "LOCK TABLE", primary, stmt, out)
}

func (g *Gatekeeper) inspectCluster(tokens []Token, stmt Statement, session *SessionState, out *[]Hazard) {
	i := 1
	if i < len(tokens) && isWord(tokens[i], "VERBOSE") {
		i++
	}
	// Skip optional parenthesized options: CLUSTER (VERBOSE) table
	if i < len(tokens) && tokens[i].Kind == TokLParen {
		i = skipBalancedParens(tokens, i)
	}
	tbl := ""
	if i < len(tokens) && !isWord(tokens[i], "USING") {
		tbl, _ = parseTableName(tokens, i)
	}
	if g.isTableAllowlisted(tbl) {
		return
	}
	g.checkLockTimeout(session, "CLUSTER", tbl, stmt, out)
}

func (g *Gatekeeper) inspectReindex(tokens []Token, stmt Statement, session *SessionState, out *[]Hazard) {
	// REINDEX [ ( option [, ...] ) ] { INDEX | TABLE | SCHEMA | DATABASE | SYSTEM } [ CONCURRENTLY ] name
	if hasTopLevelWord(tokens[1:], "CONCURRENTLY") {
		return
	}
	if len(tokens) >= 2 && tokens[1].Kind == TokLParen {
		end := skipBalancedParens(tokens, 1)
		if optionEnabled(tokens[2:end-1], "CONCURRENTLY") {
			return
		}
	}
	g.checkLockTimeout(session, "REINDEX", "", stmt, out)
}

func (g *Gatekeeper) inspectCreate(tokens []Token, stmt Statement, out *[]Hazard) {
	i := 1
	if i < len(tokens) && isWord(tokens[i], "UNIQUE") {
		i++
	}
	if i >= len(tokens) || !isWord(tokens[i], "INDEX") {
		return
	}
	i++
	// Check for CONCURRENTLY before ON
	concurrent := false
	tbl := ""
	depth := 0
	for k := i; k < len(tokens); k++ {
		if tokens[k].Kind == TokLParen {
			depth++
			continue
		}
		if tokens[k].Kind == TokRParen {
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 {
			continue
		}
		if isWord(tokens[k], "CONCURRENTLY") {
			concurrent = true
		}
		if isWord(tokens[k], "ON") {
			next := k + 1
			if next < len(tokens) && isWord(tokens[next], "ONLY") {
				next++
			}
			tbl, _ = parseTableName(tokens, next)
			break
		}
	}
	if concurrent || g.isTableAllowlisted(tbl) {
		return
	}
	g.addHazard(out, Hazard{
		Type:        HazardNonConcurrentIndex,
		Severity:    SeverityHigh,
		SQLState:    "54000",
		Message:     "Pyx Gatekeeper: Non-concurrent index creation blocked",
		Detail:      "Creating indexes without CONCURRENTLY takes a SHARE table lock, blocking write operations during index population. Use CREATE INDEX CONCURRENTLY.",
		Remediation: "Use CREATE [UNIQUE] INDEX CONCURRENTLY.",
		Table:       tbl,
	}, stmt)
}

func (g *Gatekeeper) inspectVacuum(tokens []Token, stmt Statement, out *[]Hazard) {
	isFull := false
	if len(tokens) >= 2 && isWord(tokens[1], "FULL") {
		isFull = true
	} else if len(tokens) >= 2 && tokens[1].Kind == TokLParen {
		end := skipBalancedParens(tokens, 1)
		if end > 2 && optionEnabled(tokens[2:end-1], "FULL") {
			isFull = true
		}
	}
	if !isFull {
		return
	}
	g.addHazard(out, Hazard{
		Type:        HazardVacuumFull,
		Severity:    SeverityHigh,
		SQLState:    "55P03",
		Message:     "Pyx Gatekeeper: VACUUM FULL execution prohibited",
		Detail:      "VACUUM FULL locks the entire table against both reads and writes until rewrites finish. Use pg_repack or incremental vacuum.",
		Remediation: "Use standard VACUUM or pg_repack for online table compaction.",
	}, stmt)
}

func (g *Gatekeeper) inspectMutation(tokens []Token, stmt Statement, out *[]Hazard) {
	if len(tokens) < 2 || tokens[0].Kind != TokWord {
		return
	}

	var op string
	var table string
	var searchFrom int

	switch tokens[0].Upper {
	case "UPDATE":
		op = "UPDATE"
		i := 1
		if i < len(tokens) && isWord(tokens[i], "ONLY") {
			i++
		}
		var next int
		table, next = parseTableName(tokens, i)
		if table == "" {
			return
		}
		// Locate top-level SET after table (and optional alias)
		setIdx := findTopLevelWord(tokens, next, "SET")
		if setIdx < 0 {
			return
		}
		searchFrom = setIdx + 1

	case "DELETE":
		op = "DELETE"
		if !isWord(tokens[1], "FROM") {
			return
		}
		i := 2
		if i < len(tokens) && isWord(tokens[i], "ONLY") {
			i++
		}
		var next int
		table, next = parseTableName(tokens, i)
		if table == "" {
			return
		}
		searchFrom = next

	default:
		return
	}

	if g.isTableAllowlisted(table) {
		return
	}

	whereIdx := findTopLevelWord(tokens, searchFrom, "WHERE")
	if whereIdx < 0 {
		g.addHazard(out, Hazard{
			Type:        HazardUnqualifiedMutation,
			Severity:    SeverityHigh,
			SQLState:    "54000",
			Message:     "Pyx Gatekeeper: Unqualified bulk table mutation prohibited",
			Detail:      fmt.Sprintf("%s statement on %q detected with zero WHERE qualification, which would mutate or delete all records in the table.", op, table),
			Remediation: "Supply an explicit row-filtering WHERE predicate.",
			Table:       table,
		}, stmt)
		return
	}

	// Extract top-level predicate tokens between WHERE and optional RETURNING
	predEnd := findTopLevelWord(tokens, whereIdx+1, "RETURNING")
	if predEnd < 0 {
		predEnd = len(tokens)
	}
	pred := tokens[whereIdx+1 : predEnd]
	if isTautology(pred) {
		g.addHazard(out, Hazard{
			Type:        HazardUnqualifiedMutation,
			Severity:    SeverityHigh,
			SQLState:    "54000",
			Message:     "Pyx Gatekeeper: Tautological WHERE clause on bulk table mutation prohibited",
			Detail:      fmt.Sprintf("%s statement on %q uses a tautological WHERE predicate that evaluates to true for every row.", op, table),
			Remediation: "Replace the always-true WHERE condition with a selective row predicate.",
			Table:       table,
		}, stmt)
	}
}

// isTautology evaluates whether a WHERE predicate token slice is unconditionally true
// (e.g. TRUE, NOT FALSE, 1=1, 'a'='a', id=1 OR 1=1) while preserving dynamic query
// builder patterns such as WHERE 1=1 AND user_id = $1.
func isTautology(tokens []Token) bool {
	tokens = stripOuterParens(tokens)
	if len(tokens) == 0 {
		return false
	}

	// Split by top-level OR: if ANY OR-branch is unconditionally true, the predicate is a tautology.
	orBranches := splitTopLevelKeyword(tokens, "OR")
	if len(orBranches) > 1 {
		for _, b := range orBranches {
			if isTautology(b) {
				return true
			}
		}
		return false
	}

	// Split by top-level AND: only unconditionally true if ALL AND-branches are tautologies.
	andBranches := splitTopLevelKeyword(tokens, "AND")
	if len(andBranches) > 1 {
		for _, b := range andBranches {
			if !isTautology(b) {
				return false
			}
		}
		return true
	}

	// Single atomic expression
	if len(tokens) == 1 {
		return isWord(tokens[0], "TRUE")
	}
	if len(tokens) == 2 && isWord(tokens[0], "NOT") && isWord(tokens[1], "FALSE") {
		return true
	}
	if len(tokens) == 3 {
		// NULL IS NULL
		if isWord(tokens[0], "NULL") && isWord(tokens[1], "IS") && isWord(tokens[2], "NULL") {
			return true
		}
		if tokens[1].Kind == TokOp {
			return evalConstComparison(tokens[0], tokens[1].Raw, tokens[2])
		}
	}
	// <literal> IS NOT NULL
	if len(tokens) == 4 && isWord(tokens[1], "IS") && isWord(tokens[2], "NOT") && isWord(tokens[3], "NULL") {
		if tokens[0].Kind == TokNumber || tokens[0].Kind == TokString || isWord(tokens[0], "TRUE") || isWord(tokens[0], "FALSE") {
			return true
		}
	}
	return false
}

func evalConstComparison(lhs Token, op string, rhs Token) bool {
	// Numeric comparison
	if lhs.Kind == TokNumber && rhs.Kind == TokNumber {
		a, err1 := strconv.ParseFloat(lhs.Raw, 64)
		b, err2 := strconv.ParseFloat(rhs.Raw, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		switch op {
		case "=":
			return a == b
		case "!=", "<>":
			return a != b
		case "<":
			return a < b
		case "<=":
			return a <= b
		case ">":
			return a > b
		case ">=":
			return a >= b
		}
		return false
	}

	// String literal comparison
	if lhs.Kind == TokString && rhs.Kind == TokString {
		switch op {
		case "=":
			return lhs.Raw == rhs.Raw
		case "!=", "<>":
			return lhs.Raw != rhs.Raw
		case "<":
			return lhs.Raw < rhs.Raw
		case "<=":
			return lhs.Raw <= rhs.Raw
		case ">":
			return lhs.Raw > rhs.Raw
		case ">=":
			return lhs.Raw >= rhs.Raw
		}
		return false
	}

	// Boolean literal comparison
	lb, ok1 := parseBoolWord(lhs)
	rb, ok2 := parseBoolWord(rhs)
	if ok1 && ok2 {
		switch op {
		case "=":
			return lb == rb
		case "!=", "<>":
			return lb != rb
		}
	}
	return false
}

func parseBoolWord(t Token) (bool, bool) {
	if t.Kind != TokWord {
		return false, false
	}
	if t.Upper == "TRUE" {
		return true, true
	}
	if t.Upper == "FALSE" {
		return false, true
	}
	return false, false
}

func stripOuterParens(tokens []Token) []Token {
	for len(tokens) >= 2 && tokens[0].Kind == TokLParen && tokens[len(tokens)-1].Kind == TokRParen {
		// Verify opening paren at 0 matches the very last token
		depth := 0
		matchedEnd := false
		for i, tok := range tokens {
			if tok.Kind == TokLParen {
				depth++
			} else if tok.Kind == TokRParen {
				depth--
				if depth == 0 {
					matchedEnd = (i == len(tokens)-1)
					break
				}
			}
		}
		if !matchedEnd {
			break
		}
		tokens = tokens[1 : len(tokens)-1]
	}
	return tokens
}

func splitTopLevelKeyword(tokens []Token, kw string) [][]Token {
	var parts [][]Token
	depth := 0
	start := 0
	for i, tok := range tokens {
		switch tok.Kind {
		case TokLParen:
			depth++
		case TokRParen:
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && isWord(tok, kw) {
				parts = append(parts, tokens[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, tokens[start:])
	return parts
}

func splitTopLevelComma(tokens []Token) [][]Token {
	var parts [][]Token
	depth := 0
	start := 0
	for i, tok := range tokens {
		switch tok.Kind {
		case TokLParen:
			depth++
		case TokRParen:
			if depth > 0 {
				depth--
			}
		case TokComma:
			if depth == 0 {
				if i > start {
					parts = append(parts, tokens[start:i])
				}
				start = i + 1
			}
		}
	}
	if start < len(tokens) {
		parts = append(parts, tokens[start:])
	}
	return parts
}

func splitLeadingCTEs(tokens []Token) (rest []Token, bodies [][]Token) {
	i := 1 // skip WITH
	if i < len(tokens) && isWord(tokens[i], "RECURSIVE") {
		i++
	}
	for i < len(tokens) {
		// CTE name
		if tokens[i].Kind != TokWord && tokens[i].Kind != TokIdent {
			return tokens[i:], bodies
		}
		i++
		// Optional column list (...)
		if i < len(tokens) && tokens[i].Kind == TokLParen {
			i = skipBalancedParens(tokens, i)
		}
		// Expect AS
		if i >= len(tokens) || !isWord(tokens[i], "AS") {
			return tokens[i:], bodies
		}
		i++
		// Optional NOT MATERIALIZED / MATERIALIZED
		if i < len(tokens) && isWord(tokens[i], "NOT") {
			i++
		}
		if i < len(tokens) && isWord(tokens[i], "MATERIALIZED") {
			i++
		}
		if i >= len(tokens) || tokens[i].Kind != TokLParen {
			return tokens[i:], bodies
		}
		end := skipBalancedParens(tokens, i)
		if end > i+1 {
			bodies = append(bodies, tokens[i+1:end-1])
		}
		i = end
		// Optional SEARCH / CYCLE clauses ignored until comma or main keyword
		if i < len(tokens) && tokens[i].Kind == TokComma {
			i++
			continue
		}
		return tokens[i:], bodies
	}
	return nil, bodies
}

func skipBalancedParens(tokens []Token, openIdx int) int {
	depth := 0
	for i := openIdx; i < len(tokens); i++ {
		if tokens[i].Kind == TokLParen {
			depth++
		} else if tokens[i].Kind == TokRParen {
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(tokens)
}

func parseTableName(tokens []Token, start int) (string, int) {
	if start >= len(tokens) {
		return "", start
	}
	if tokens[start].Kind != TokWord && tokens[start].Kind != TokIdent {
		return "", start
	}
	var parts []string
	parts = append(parts, tokens[start].Raw)
	i := start + 1
	for i+1 < len(tokens) && tokens[i].Kind == TokDot && (tokens[i+1].Kind == TokWord || tokens[i+1].Kind == TokIdent) {
		parts = append(parts, tokens[i+1].Raw)
		i += 2
	}
	return strings.Join(parts, "."), i
}

func parseTableList(tokens []Token, start int, stopWords map[string]bool) []string {
	var tables []string
	i := start
	for i < len(tokens) {
		if tokens[i].Kind == TokWord && stopWords[tokens[i].Upper] {
			break
		}
		if isWord(tokens[i], "ONLY") {
			i++
		}
		tbl, next := parseTableName(tokens, i)
		if tbl == "" {
			break
		}
		tables = append(tables, tbl)
		i = next
		if i < len(tokens) && tokens[i].Kind == TokComma {
			i++
			continue
		}
		break
	}
	return tables
}

func findTopLevelWord(tokens []Token, start int, upper string) int {
	depth := 0
	for i := start; i < len(tokens); i++ {
		switch tokens[i].Kind {
		case TokLParen:
			depth++
		case TokRParen:
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && isWord(tokens[i], upper) {
				return i
			}
		}
	}
	return -1
}

func hasTopLevelWord(tokens []Token, upper string) bool {
	return findTopLevelWord(tokens, 0, upper) >= 0
}

func optionEnabled(optTokens []Token, optUpper string) bool {
	for i := 0; i < len(optTokens); i++ {
		if isWord(optTokens[i], optUpper) {
			if i+1 < len(optTokens) && optTokens[i+1].Kind != TokComma {
				val := strings.ToUpper(optTokens[i+1].Raw)
				if val == "FALSE" || val == "OFF" || val == "0" {
					return false
				}
			}
			return true
		}
	}
	return false
}

func isWord(t Token, upper string) bool {
	return t.Kind == TokWord && t.Upper == upper
}
