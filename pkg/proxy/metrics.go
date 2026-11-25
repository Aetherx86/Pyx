package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/omakasekim/Pyx/pkg/gatekeeper"
)

const defaultLatencyWindow = 4096

// LatencyStats summarizes observed latencies in microseconds.
type LatencyStats struct {
	Count  uint64  `json:"count"`
	MinUS  float64 `json:"min_us"`
	MeanUS float64 `json:"mean_us"`
	P50US  float64 `json:"p50_us"`
	P95US  float64 `json:"p95_us"`
	P99US  float64 `json:"p99_us"`
	MaxUS  float64 `json:"max_us"`
}

// Metrics is a race-safe point-in-time snapshot of proxy telemetry.
type Metrics struct {
	StartedAt         time.Time                        `json:"started_at"`
	UptimeSeconds     float64                          `json:"uptime_seconds"`
	Mode              string                           `json:"mode"`
	TotalConnections  uint64                           `json:"total_connections"`
	ActiveConnections int64                            `json:"active_connections"`
	TotalQueries      uint64                           `json:"total_queries"`
	SimpleQueries     uint64                           `json:"simple_queries"`
	ExtendedQueries   uint64                           `json:"extended_queries"`
	AllowedQueries    uint64                           `json:"allowed_queries"`
	BlockedQueries    uint64                           `json:"blocked_queries"`
	AuditAlertQueries uint64                           `json:"audit_alert_queries"`
	HazardsDetected   uint64                           `json:"hazards_detected"`
	HazardsByType     map[gatekeeper.HazardType]uint64 `json:"hazards_by_type"`
	InspectionLatency LatencyStats                     `json:"inspection_latency"`
	BackendLatency    LatencyStats                     `json:"backend_latency"`
}

// MarshalJSONReport formats Metrics as indented JSON.
func (m Metrics) MarshalJSONReport() ([]byte, error) {
	if m.HazardsByType == nil {
		m.HazardsByType = map[gatekeeper.HazardType]uint64{}
	}
	return json.MarshalIndent(m, "", "  ")
}

// AuditEvent represents a single structured NDJSON audit record emitted by the proxy.
type AuditEvent struct {
	Timestamp     time.Time           `json:"timestamp"`
	ClientAddr    string              `json:"client_addr"`
	User          string              `json:"user,omitempty"`
	Database      string              `json:"database,omitempty"`
	ProtocolMsg   string              `json:"protocol_msg"`
	StatementName string              `json:"statement_name,omitempty"`
	Decision      string              `json:"decision"`
	InspectionUS  float64             `json:"inspection_us"`
	SQLHash       string              `json:"sql_hash"`
	SQL           string              `json:"sql"`
	Hazards       []gatekeeper.Hazard `json:"hazards,omitempty"`
}

type latencyTracker struct {
	mu      sync.Mutex
	samples []int64
	pos     int
	full    bool
	count   uint64
	sumNs   int64
	minNs   int64
	maxNs   int64
}

func newLatencyTracker(capacity int) *latencyTracker {
	if capacity <= 0 {
		capacity = defaultLatencyWindow
	}
	return &latencyTracker{
		samples: make([]int64, capacity),
	}
}

func (lt *latencyTracker) Observe(d time.Duration) {
	ns := d.Nanoseconds()
	if ns < 0 {
		ns = 0
	}
	lt.mu.Lock()
	if lt.count == 0 {
		lt.minNs = ns
		lt.maxNs = ns
	} else {
		if ns < lt.minNs {
			lt.minNs = ns
		}
		if ns > lt.maxNs {
			lt.maxNs = ns
		}
	}
	lt.count++
	lt.sumNs += ns
	lt.samples[lt.pos] = ns
	lt.pos++
	if lt.pos == len(lt.samples) {
		lt.pos = 0
		lt.full = true
	}
	lt.mu.Unlock()
}

func (lt *latencyTracker) Snapshot() LatencyStats {
	lt.mu.Lock()
	if lt.count == 0 {
		lt.mu.Unlock()
		return LatencyStats{}
	}
	n := lt.pos
	if lt.full {
		n = len(lt.samples)
	}
	buf := make([]int64, n)
	copy(buf, lt.samples[:n])
	count := lt.count
	sumNs := lt.sumNs
	minNs := lt.minNs
	maxNs := lt.maxNs
	lt.mu.Unlock()

	slices.Sort(buf)
	return LatencyStats{
		Count:  count,
		MinUS:  roundUS(float64(minNs) / 1000.0),
		MeanUS: roundUS(float64(sumNs) / float64(count) / 1000.0),
		P50US:  roundUS(float64(percentileNs(buf, 0.50)) / 1000.0),
		P95US:  roundUS(float64(percentileNs(buf, 0.95)) / 1000.0),
		P99US:  roundUS(float64(percentileNs(buf, 0.99)) / 1000.0),
		MaxUS:  roundUS(float64(maxNs) / 1000.0),
	}
}

func percentileNs(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Ceil(p*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func roundUS(v float64) float64 {
	return math.Round(v*1000.0) / 1000.0
}

type metricsCollector struct {
	startedAt         time.Time
	mode              string
	totalConnections  atomic.Uint64
	activeConnections atomic.Int64
	totalQueries      atomic.Uint64
	simpleQueries     atomic.Uint64
	extendedQueries   atomic.Uint64
	allowedQueries    atomic.Uint64
	blockedQueries    atomic.Uint64
	auditAlertQueries atomic.Uint64
	hazardsDetected   atomic.Uint64

	hazardMu      sync.Mutex
	hazardsByType map[gatekeeper.HazardType]uint64

	inspectionLatency *latencyTracker
	backendLatency    *latencyTracker
}

func newMetricsCollector(strict bool) *metricsCollector {
	mode := "audit"
	if strict {
		mode = "strict"
	}
	return &metricsCollector{
		startedAt:         time.Now().UTC(),
		mode:              mode,
		hazardsByType:     make(map[gatekeeper.HazardType]uint64),
		inspectionLatency: newLatencyTracker(defaultLatencyWindow),
		backendLatency:    newLatencyTracker(defaultLatencyWindow),
	}
}

func (c *metricsCollector) RecordHazards(hazards []gatekeeper.Hazard) {
	if len(hazards) == 0 {
		return
	}
	c.hazardsDetected.Add(uint64(len(hazards)))
	c.hazardMu.Lock()
	for _, h := range hazards {
		c.hazardsByType[h.Type]++
	}
	c.hazardMu.Unlock()
}

func (c *metricsCollector) Snapshot() Metrics {
	c.hazardMu.Lock()
	byType := make(map[gatekeeper.HazardType]uint64, len(c.hazardsByType))
	for k, v := range c.hazardsByType {
		byType[k] = v
	}
	c.hazardMu.Unlock()

	return Metrics{
		StartedAt:         c.startedAt,
		UptimeSeconds:     roundUS(time.Since(c.startedAt).Seconds()),
		Mode:              c.mode,
		TotalConnections:  c.totalConnections.Load(),
		ActiveConnections: c.activeConnections.Load(),
		TotalQueries:      c.totalQueries.Load(),
		SimpleQueries:     c.simpleQueries.Load(),
		ExtendedQueries:   c.extendedQueries.Load(),
		AllowedQueries:    c.allowedQueries.Load(),
		BlockedQueries:    c.blockedQueries.Load(),
		AuditAlertQueries: c.auditAlertQueries.Load(),
		HazardsDetected:   c.hazardsDetected.Load(),
		HazardsByType:     byType,
		InspectionLatency: c.inspectionLatency.Snapshot(),
		BackendLatency:    c.backendLatency.Snapshot(),
	}
}

type auditLogger struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func newAuditLogger(w io.Writer) *auditLogger {
	if w == nil {
		return nil
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &auditLogger{enc: enc}
}

func (a *auditLogger) Log(ev AuditEvent) {
	if a == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	sum := sha256.Sum256([]byte(ev.SQL))
	ev.SQLHash = hex.EncodeToString(sum[:8])
	if len(ev.SQL) > 2048 {
		ev.SQL = ev.SQL[:2048] + "...[truncated]"
	}
	a.mu.Lock()
	_ = a.enc.Encode(ev)
	a.mu.Unlock()
}
