package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/omakasekim/Pyx/pkg/gatekeeper"
)

func TestCLIVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--version"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), Version) {
		t.Fatalf("expected version %s in stdout, got %q", Version, stdout.String())
	}
}

func TestCLIInspectInlineJSONAndText(t *testing.T) {
	// Strict mode on hazardous query -> exit 1 with valid JSON report
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--inspect", "ALTER TABLE users ADD COLUMN phone VARCHAR(20);",
		"--mode", "strict",
		"--format", "json",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 on hazardous query in strict mode, got %d (stderr=%q)", code, stderr.String())
	}
	var report gatekeeper.InspectReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("failed to parse JSON report: %v (raw=%q)", err, stdout.String())
	}
	if report.Clean || !report.Blocked || report.HazardCount != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}

	// Audit mode on same hazardous query -> exit 0
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"--inspect", "ALTER TABLE users ADD COLUMN phone VARCHAR(20);",
		"--mode", "audit",
		"--format", "text",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0 in audit mode, got %d", code)
	}
	if !strings.Contains(stdout.String(), "TABLE_LOCK_DDL") {
		t.Fatalf("expected TABLE_LOCK_DDL in text output, got %q", stdout.String())
	}

	// Clean query -> exit 0
	stdout.Reset()
	code = run([]string{
		"--inspect", "SET LOCAL lock_timeout = '2s'; ALTER TABLE users ADD COLUMN phone VARCHAR(20);",
		"--mode", "strict",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0 on clean query, got %d (out=%q)", code, stdout.String())
	}
}

func TestCLIInspectFileAndStdinWithPolicy(t *testing.T) {
	dir := t.TempDir()
	sqlFile := filepath.Join(dir, "migration.sql")
	sqlContent := "-- Safe migration\nSET LOCAL lock_timeout = '10s';\nALTER TABLE users ADD COLUMN bio TEXT;\n"
	if err := os.WriteFile(sqlFile, []byte(sqlContent), 0o600); err != nil {
		t.Fatalf("write sql file: %v", err)
	}

	// Exceeds --max-lock-timeout 5s -> exit 1
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"--inspect-file", sqlFile,
		"--max-lock-timeout", "5s",
		"--format", "json",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 when lock_timeout exceeds max-lock-timeout, got %d", code)
	}
	var report gatekeeper.InspectReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("unmarshal file report: %v", err)
	}
	if report.Source != sqlFile || report.HazardCount == 0 {
		t.Fatalf("unexpected file report: %+v", report)
	}

	// Stdin inspection with policy file allowlisting table
	policyFile := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policyFile, []byte(`{"strict_mode":true,"allowlisted_tables":["scratch_events"]}`), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"--inspect-file", "-",
		"--policy", policyFile,
		"--format", "json",
	}, strings.NewReader("DELETE FROM scratch_events;"), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0 for allowlisted table via stdin, got %d (out=%q err=%q)", code, stdout.String(), stderr.String())
	}
}

func TestCLIInvalidFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--mode", "invalid"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 on invalid mode, got %d", code)
	}
	stderr.Reset()
	if code := run([]string{"--format", "xml"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 on invalid format, got %d", code)
	}
	stderr.Reset()
	if code := run([]string{"--max-lock-timeout", "0s"}, strings.NewReader(""), &stdout, &stderr); code != 2 {
		t.Fatalf("expected exit 2 on zero max-lock-timeout, got %d", code)
	}
}
