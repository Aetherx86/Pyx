package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Aetherx86/Pyx/pkg/gatekeeper"
	"github.com/Aetherx86/Pyx/pkg/proxy"
)

const Version = "1.0.0"

func main() {
	listenAddr := flag.String("listen", ":5433", "TCP address to listen for PostgreSQL client connections")
	targetAddr := flag.String("target", "localhost:5432", "Target PostgreSQL server address")
	mode := flag.String("mode", "strict", "Operational mode: 'strict' (reject hazardous queries) or 'audit' (log only)")
	inspectQuery := flag.String("inspect", "", "Standalone mode: inspect a SQL string for hazards without starting proxy")
	verbose := flag.Bool("verbose", true, "Enable detailed wire interception logs")
	showVersion := flag.Bool("version", false, "Print Pyx version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Printf("Pyx PostgreSQL Wire-Protocol Proxy & Query Gatekeeper v%s\n", Version)
		os.Exit(0)
	}

	// Standalone SQL inspection mode
	if *inspectQuery != "" {
		gk := gatekeeper.New(strings.ToLower(*mode) == "strict")
		hazards := gk.Inspect(*inspectQuery)
		if len(hazards) == 0 {
			fmt.Println("Pyx Gatekeeper: Clean. Zero database wire hazards identified.")
			os.Exit(0)
		}
		fmt.Printf("Pyx Gatekeeper: %d hazard(s) identified:\n\n", len(hazards))
		fmt.Print(gatekeeper.FormatHazards(hazards))
		if strings.ToLower(*mode) == "strict" {
			os.Exit(1)
		}
		os.Exit(0)
	}

	isStrict := strings.ToLower(*mode) == "strict"
	cfg := proxy.Config{
		ListenAddr: *listenAddr,
		TargetAddr: *targetAddr,
		StrictMode: isStrict,
		Verbose:    *verbose,
	}

	srv := proxy.NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[pyx] shutdown signal received, draining connections...")
		cancel()
		_ = srv.Close()
	}()

	modeLabel := "STRICT (active wire rejection)"
	if !isStrict {
		modeLabel = "AUDIT (passive telemetry logging)"
	}

	log.Printf("[pyx] starting PostgreSQL 3.0 wire gatekeeper on %s -> %s [mode: %s]",
		*listenAddr, *targetAddr, modeLabel)

	if err := srv.Start(ctx); err != nil {
		log.Fatalf("[pyx] fatal server error: %v", err)
	}

	m := srv.GetMetrics()
	log.Printf("[pyx] shutdown complete. Total connections: %d, Queries: %d, Hazards: %d, Blocked: %d",
		m.TotalConnections, m.TotalQueries, m.HazardsDetected, m.BlockedQueries)
}
