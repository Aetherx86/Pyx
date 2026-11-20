package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Aetherx86/Pyx/pkg/gatekeeper"
	"github.com/Aetherx86/Pyx/pkg/proxy"
)

const Version = "0.2.0"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("pyx", flag.ContinueOnError)
	fs.SetOutput(stderr)

	listenAddr := fs.String("listen", ":5433", "TCP address to listen for PostgreSQL client connections")
	targetAddr := fs.String("target", "localhost:5432", "Target PostgreSQL server address")
	mode := fs.String("mode", "strict", "Operational mode: 'strict' (reject hazardous queries) or 'audit' (log only)")
	inspectQuery := fs.String("inspect", "", "Standalone mode: inspect a SQL string for hazards without starting proxy")
	inspectFile := fs.String("inspect-file", "", "Standalone mode: inspect a SQL file (or '-' for stdin) for hazards")
	format := fs.String("format", "text", "Output format for standalone inspection: 'text' or 'json'")
	policyPath := fs.String("policy", "", "Path to JSON policy configuration file")
	maxLockTimeout := fs.String("max-lock-timeout", "", "Maximum permitted lock_timeout duration (e.g. '5s', '500ms')")
	auditLogPath := fs.String("audit-log", "", "File path (or '-' for stdout) for NDJSON audit trail logging")
	metricsAddr := fs.String("metrics-addr", "", "Optional HTTP listen address for /metrics JSON and /healthz (e.g. '127.0.0.1:9090')")
	reportJSONPath := fs.String("report-json", "", "Optional file path to write final JSON metrics report on shutdown")
	verbose := fs.Bool("verbose", true, "Enable detailed wire interception logs")
	showVersion := fs.Bool("version", false, "Print Pyx version and exit")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *showVersion {
		fmt.Fprintf(stdout, "Pyx PostgreSQL Wire-Protocol Proxy & Query Gatekeeper v%s\n", Version)
		return 0
	}

	explicitFlags := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		explicitFlags[f.Name] = true
	})

	modeLower := strings.ToLower(strings.TrimSpace(*mode))
	if modeLower != "strict" && modeLower != "audit" {
		fmt.Fprintf(stderr, "pyx: invalid --mode %q (expected 'strict' or 'audit')\n", *mode)
		return 2
	}
	formatLower := strings.ToLower(strings.TrimSpace(*format))
	if formatLower != "text" && formatLower != "json" {
		fmt.Fprintf(stderr, "pyx: invalid --format %q (expected 'text' or 'json')\n", *format)
		return 2
	}

	pol := gatekeeper.DefaultPolicy(modeLower == "strict")
	if *policyPath != "" {
		loaded, err := gatekeeper.LoadPolicyFile(*policyPath)
		if err != nil {
			fmt.Fprintf(stderr, "pyx: failed to load policy: %v\n", err)
			return 2
		}
		pol = loaded
		if explicitFlags["mode"] {
			pol.StrictMode = (modeLower == "strict")
		}
	}
	if *maxLockTimeout != "" {
		pol.MaxLockTimeout = *maxLockTimeout
	}
	if err := pol.Validate(); err != nil {
		fmt.Fprintf(stderr, "pyx: invalid policy configuration: %v\n", err)
		return 2
	}

	// Standalone SQL inspection mode (inline or file/stdin)
	if *inspectQuery != "" || *inspectFile != "" {
		sqlText := *inspectQuery
		source := "<inline>"
		if *inspectFile != "" {
			source = *inspectFile
			var raw []byte
			var err error
			if *inspectFile == "-" {
				source = "<stdin>"
				raw, err = io.ReadAll(stdin)
			} else {
				raw, err = os.ReadFile(*inspectFile)
			}
			if err != nil {
				fmt.Fprintf(stderr, "pyx: failed to read SQL input %s: %v\n", source, err)
				return 2
			}
			sqlText = string(raw)
		}

		gk := gatekeeper.NewWithPolicy(pol)
		report := gk.BuildReport(sqlText, source)

		if formatLower == "json" {
			data, err := gatekeeper.FormatReportJSON(report)
			if err != nil {
				fmt.Fprintf(stderr, "pyx: failed to encode JSON report: %v\n", err)
				return 2
			}
			fmt.Fprintln(stdout, string(data))
		} else {
			if report.Clean {
				fmt.Fprintln(stdout, "Pyx Gatekeeper: Clean. Zero database wire hazards identified.")
			} else {
				fmt.Fprintf(stdout, "Pyx Gatekeeper: %d hazard(s) identified across %d statement(s):\n\n",
					report.HazardCount, report.StatementCount)
				fmt.Fprint(stdout, gatekeeper.FormatHazards(report.Hazards))
			}
		}

		if report.Blocked {
			return 1
		}
		return 0
	}

	var auditWriter io.Writer
	var auditFile *os.File
	if *auditLogPath != "" {
		if *auditLogPath == "-" {
			auditWriter = stdout
		} else {
			f, err := os.OpenFile(*auditLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				fmt.Fprintf(stderr, "pyx: failed to open audit log %q: %v\n", *auditLogPath, err)
				return 2
			}
			auditFile = f
			auditWriter = f
			defer func() { _ = auditFile.Close() }()
		}
	}

	cfg := proxy.Config{
		ListenAddr:  *listenAddr,
		TargetAddr:  *targetAddr,
		StrictMode:  pol.StrictMode,
		Policy:      &pol,
		Verbose:     *verbose,
		AuditWriter: auditWriter,
		MetricsAddr: *metricsAddr,
	}

	srv := proxy.NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			log.Println("[pyx] shutdown signal received, draining connections...")
			cancel()
			_ = srv.Close()
		case <-ctx.Done():
		}
	}()

	modeLabel := "STRICT (active wire rejection)"
	if !pol.StrictMode {
		modeLabel = "AUDIT (passive telemetry logging)"
	}

	log.Printf("[pyx] starting PostgreSQL 3.0 wire gatekeeper v%s on %s -> %s [mode: %s]",
		Version, *listenAddr, *targetAddr, modeLabel)
	if *metricsAddr != "" {
		log.Printf("[pyx] exposing telemetry HTTP endpoints on http://%s/metrics and /healthz", *metricsAddr)
	}

	if err := srv.Start(ctx); err != nil {
		log.Printf("[pyx] fatal server error: %v", err)
		return 1
	}

	m := srv.GetMetrics()
	log.Printf("[pyx] shutdown complete. Connections: %d, Queries: %d (simple: %d, extended: %d), Hazards: %d, Blocked: %d, Inspect p95: %.2fus",
		m.TotalConnections, m.TotalQueries, m.SimpleQueries, m.ExtendedQueries,
		m.HazardsDetected, m.BlockedQueries, m.InspectionLatency.P95US)

	if *reportJSONPath != "" {
		data, err := m.MarshalJSONReport()
		if err != nil {
			log.Printf("[pyx] failed to marshal shutdown JSON report: %v", err)
			return 1
		}
		if err := os.WriteFile(*reportJSONPath, append(data, '\n'), 0o600); err != nil {
			log.Printf("[pyx] failed to write shutdown JSON report to %q: %v", *reportJSONPath, err)
			return 1
		}
		log.Printf("[pyx] wrote shutdown telemetry JSON report to %s", *reportJSONPath)
	}

	return 0
}
