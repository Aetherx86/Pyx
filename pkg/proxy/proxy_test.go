package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/omakasekim/Pyx/pkg/gatekeeper"
	"github.com/omakasekim/Pyx/pkg/protocol"
)

// mockPostgresBackend simulates a PostgreSQL 3.0 server supporting Startup, CancelRequest,
// Simple Query ('Q'), and Extended Query ('P', 'B', 'D', 'E', 'C', 'S') with transaction status tracking.
type mockBackend struct {
	listener  net.Listener
	received  chan string
	cancels   chan int32
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func startMockPostgresBackend(t *testing.T, bufSize int) *mockBackend {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind mock backend: %v", err)
	}
	mb := &mockBackend{
		listener: l,
		received: make(chan string, bufSize),
		cancels:  make(chan int32, 16),
	}

	mb.wg.Add(1)
	go func() {
		defer mb.wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			mb.wg.Add(1)
			go func(c net.Conn) {
				defer mb.wg.Done()
				defer c.Close()
				mb.serveConn(c)
			}(conn)
		}
	}()

	return mb
}

func (mb *mockBackend) Addr() string {
	return mb.listener.Addr().String()
}

func (mb *mockBackend) Close() {
	mb.closeOnce.Do(func() {
		_ = mb.listener.Close()
	})
	mb.wg.Wait()
}

func (mb *mockBackend) serveConn(c net.Conn) {
	r := bufio.NewReader(c)
	startup, err := protocol.ReadStartupPacket(r)
	if err != nil {
		return
	}
	if code, ok := protocol.StartupCode(startup); ok && code == protocol.CancelRequestCode {
		if len(startup.Payload) >= 8 {
			pid := int32(binary.BigEndian.Uint32(startup.Payload[4:8]))
			select {
			case mb.cancels <- pid:
			default:
			}
		}
		return
	}

	// AuthenticationOk ('R', len 8, status 0)
	var authOk [9]byte
	authOk[0] = protocol.BackendAuthentication
	binary.BigEndian.PutUint32(authOk[1:5], 8)
	binary.BigEndian.PutUint32(authOk[5:9], 0)
	if _, err := c.Write(authOk[:]); err != nil {
		return
	}
	txStatus := protocol.TxIdle
	if _, err := protocol.BuildReadyForQuery(txStatus).WriteTo(c); err != nil {
		return
	}

	stmts := make(map[string]string)
	portals := make(map[string]string)

	updateTx := func(sql string) {
		up := strings.ToUpper(strings.TrimSpace(sql))
		switch {
		case strings.HasPrefix(up, "BEGIN"), strings.HasPrefix(up, "START TRANSACTION"):
			txStatus = protocol.TxInBlock
		case strings.HasPrefix(up, "COMMIT"), strings.HasPrefix(up, "ROLLBACK"), strings.HasPrefix(up, "END"):
			txStatus = protocol.TxIdle
		}
	}

	for {
		pkt, err := protocol.ReadPacket(r)
		if err != nil {
			return
		}
		switch pkt.Type {
		case protocol.MsgQuery:
			q, _ := pkt.ExtractQuery()
			updateTx(q)
			select {
			case mb.received <- q:
			default:
			}
			_, _ = protocol.BuildCommandComplete("OK").WriteTo(c)
			_, _ = protocol.BuildReadyForQuery(txStatus).WriteTo(c)

		case protocol.MsgParse:
			stmtName, q, _, _ := pkt.ExtractParse()
			stmts[stmtName] = q
			select {
			case mb.received <- "PARSE:" + stmtName + ":" + q:
			default:
			}
			_, _ = protocol.BuildParseComplete().WriteTo(c)

		case protocol.MsgBind:
			portal, stmtName, _ := pkt.ExtractBind()
			portals[portal] = stmtName
			_, _ = protocol.BuildBindComplete().WriteTo(c)

		case protocol.MsgDescribe:
			// Reply NoData ('n')
			_, _ = (&protocol.Packet{Type: protocol.BackendNoData, Length: 4}).WriteTo(c)

		case protocol.MsgExecute:
			portal, _, _ := pkt.ExtractExecute()
			if stmtName, ok := portals[portal]; ok {
				if q, ok := stmts[stmtName]; ok {
					updateTx(q)
					select {
					case mb.received <- "EXEC:" + stmtName + ":" + q:
					default:
					}
				}
			}
			_, _ = protocol.BuildCommandComplete("EXEC 1").WriteTo(c)

		case protocol.MsgClose:
			targetType, name, _ := pkt.ExtractClose()
			if targetType == 'S' {
				delete(stmts, name)
			} else {
				delete(portals, name)
			}
			_, _ = protocol.BuildCloseComplete().WriteTo(c)

		case protocol.MsgSync:
			_, _ = protocol.BuildReadyForQuery(txStatus).WriteTo(c)

		case protocol.MsgTerminate:
			return
		}
	}
}

func startTestProxy(t *testing.T, cfg Config) (*Server, context.CancelFunc) {
	t.Helper()
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := NewServer(cfg)
	go func() {
		_ = srv.Start(ctx)
	}()
	select {
	case <-srv.Ready():
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatalf("proxy server failed to become ready in time")
	}
	return srv, func() {
		cancel()
		_ = srv.Close()
	}
}

func dialAndHandshake(t *testing.T, proxyAddr string, params map[string]string) net.Conn {
	t.Helper()
	client, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	if _, err := protocol.BuildStartupPacket(params).WriteTo(client); err != nil {
		client.Close()
		t.Fatalf("failed to write startup packet: %v", err)
	}
	authPkt, err := protocol.ReadPacket(client)
	if err != nil || authPkt.Type != protocol.BackendAuthentication {
		client.Close()
		t.Fatalf("expected AuthenticationOk, got err=%v pkt=%+v", err, authPkt)
	}
	readyPkt, err := protocol.ReadPacket(client)
	if err != nil || readyPkt.Type != protocol.BackendReadyForQuery {
		client.Close()
		t.Fatalf("expected initial ReadyForQuery, got err=%v pkt=%+v", err, readyPkt)
	}
	return client
}

func sendSimpleQuery(t *testing.T, client net.Conn, sql string) (resp *protocol.Packet, txStatus byte) {
	t.Helper()
	if _, err := protocol.BuildQueryPacket(sql).WriteTo(client); err != nil {
		t.Fatalf("write query %q: %v", sql, err)
	}
	resp, err := protocol.ReadPacket(client)
	if err != nil {
		t.Fatalf("read response for %q: %v", sql, err)
	}
	ready, err := protocol.ReadPacket(client)
	if err != nil || ready.Type != protocol.BackendReadyForQuery {
		t.Fatalf("expected ReadyForQuery for %q, got err=%v pkt=%+v", sql, err, ready)
	}
	st, err := ready.ExtractReadyForQuery()
	if err != nil {
		t.Fatalf("extract ReadyForQuery status: %v", err)
	}
	return resp, st
}

func TestProxyStrictBlocking(t *testing.T) {
	mb := startMockPostgresBackend(t, 16)
	defer mb.Close()

	srv, stop := startTestProxy(t, Config{
		TargetAddr: mb.Addr(),
		StrictMode: true,
		Verbose:    false,
	})
	defer stop()

	client := dialAndHandshake(t, srv.Addr().String(), map[string]string{"user": "alice", "database": "app"})
	defer client.Close()

	// 1. Safe query flows to backend
	safeSQL := "SELECT 1;"
	resp, tx := sendSimpleQuery(t, client, safeSQL)
	if resp.Type != protocol.BackendCommandComplete || tx != protocol.TxIdle {
		t.Fatalf("expected CommandComplete + Idle, got type=%c tx=%c", resp.Type, tx)
	}
	select {
	case q := <-mb.received:
		if q != safeSQL {
			t.Fatalf("backend got %q, expected %q", q, safeSQL)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("backend timed out waiting for safe query")
	}

	// 2. Dangerous unconstrained ALTER TABLE is blocked on the wire
	badSQL := "ALTER TABLE customers ADD COLUMN balance INT;"
	errReply, tx := sendSimpleQuery(t, client, badSQL)
	if errReply.Type != protocol.BackendErrorResponse || tx != protocol.TxIdle {
		t.Fatalf("expected ErrorResponse + Idle, got type=%c tx=%c", errReply.Type, tx)
	}
	fields, err := protocol.ParseErrorResponse(errReply)
	if err != nil || fields.Code != "55P03" || fields.Severity != "ERROR" {
		t.Fatalf("unexpected ErrorResponse fields: %+v (err=%v)", fields, err)
	}

	// Backend MUST NOT have received the bad query
	select {
	case q := <-mb.received:
		t.Fatalf("backend received forbidden query %q", q)
	case <-time.After(80 * time.Millisecond):
	}

	// 3. Connection remains healthy for subsequent queries
	resp2, _ := sendSimpleQuery(t, client, "SELECT 2;")
	if resp2.Type != protocol.BackendCommandComplete {
		t.Fatalf("expected subsequent query to succeed, got type=%c", resp2.Type)
	}

	metrics := srv.GetMetrics()
	if metrics.TotalQueries != 3 || metrics.BlockedQueries != 1 || metrics.AllowedQueries != 2 {
		t.Fatalf("unexpected metrics: %+v", metrics)
	}
	if metrics.HazardsByType[gatekeeper.HazardTableLockDDL] != 1 {
		t.Fatalf("expected HazardsByType[TABLE_LOCK_DDL]=1, got %+v", metrics.HazardsByType)
	}
}

func TestProxyAuditModeAndNDJSONLog(t *testing.T) {
	mb := startMockPostgresBackend(t, 16)
	defer mb.Close()

	var auditBuf bytes.Buffer
	srv, stop := startTestProxy(t, Config{
		TargetAddr:  mb.Addr(),
		StrictMode:  false,
		Verbose:     false,
		AuditWriter: &auditBuf,
	})
	defer stop()

	client := dialAndHandshake(t, srv.Addr().String(), map[string]string{
		"user":     "auditor",
		"database": "analytics",
	})
	defer client.Close()

	badSQL := "DELETE FROM audit_logs;"
	resp, _ := sendSimpleQuery(t, client, badSQL)
	if resp.Type != protocol.BackendCommandComplete {
		t.Fatalf("expected audit mode to forward query, got type=%c", resp.Type)
	}
	select {
	case q := <-mb.received:
		if q != badSQL {
			t.Fatalf("backend got %q, expected %q", q, badSQL)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("backend did not receive audited query")
	}

	metrics := srv.GetMetrics()
	if metrics.BlockedQueries != 0 || metrics.AuditAlertQueries != 1 || metrics.HazardsDetected != 1 {
		t.Fatalf("unexpected audit metrics: %+v", metrics)
	}

	var ev AuditEvent
	if err := json.Unmarshal(bytes.TrimSpace(auditBuf.Bytes()), &ev); err != nil {
		t.Fatalf("unmarshal NDJSON audit event: %v (raw=%q)", err, auditBuf.String())
	}
	if ev.Decision != "AUDIT" || ev.User != "auditor" || ev.Database != "analytics" || len(ev.Hazards) != 1 || ev.SQLHash == "" {
		t.Fatalf("unexpected AuditEvent: %+v", ev)
	}
}

func TestProxyExtendedQueryProtocolBlockingAndRecovery(t *testing.T) {
	mb := startMockPostgresBackend(t, 32)
	defer mb.Close()

	srv, stop := startTestProxy(t, Config{
		TargetAddr: mb.Addr(),
		StrictMode: true,
	})
	defer stop()

	client := dialAndHandshake(t, srv.Addr().String(), map[string]string{"user": "pgx_client"})
	defer client.Close()

	// 1. Send hazardous extended query pipeline: Parse -> Bind -> Describe -> Execute -> Sync
	pipeline := []*protocol.Packet{
		protocol.BuildParsePacket("bad_stmt", "UPDATE accounts SET balance = 0 WHERE 1 = 1"),
		protocol.BuildBindPacket("p1", "bad_stmt"),
		protocol.BuildDescribePacket('P', "p1"),
		protocol.BuildExecutePacket("p1", 0),
		protocol.BuildSyncPacket(),
	}
	for _, p := range pipeline {
		if _, err := p.WriteTo(client); err != nil {
			t.Fatalf("write extended packet: %v", err)
		}
	}

	// Expect exactly [ErrorResponse(54000), ReadyForQuery('I')]
	errPkt, err := protocol.ReadPacket(client)
	if err != nil || errPkt.Type != protocol.BackendErrorResponse {
		t.Fatalf("expected ErrorResponse, got err=%v pkt=%+v", err, errPkt)
	}
	fields, _ := protocol.ParseErrorResponse(errPkt)
	if fields.Code != "54000" {
		t.Fatalf("expected SQLSTATE 54000, got %s", fields.Code)
	}
	readyPkt, err := protocol.ReadPacket(client)
	if err != nil || readyPkt.Type != protocol.BackendReadyForQuery {
		t.Fatalf("expected ReadyForQuery after Sync, got err=%v pkt=%+v", err, readyPkt)
	}

	// Backend MUST NOT have received ANY packet from the blocked extended pipeline
	select {
	case msg := <-mb.received:
		t.Fatalf("backend received forbidden extended message: %q", msg)
	case <-time.After(80 * time.Millisecond):
	}

	// 2. Follow immediately with a safe extended query pipeline on the SAME connection
	safePipeline := []*protocol.Packet{
		protocol.BuildParsePacket("good_stmt", "SELECT id FROM accounts WHERE id = $1", 23),
		protocol.BuildBindPacket("p2", "good_stmt"),
		protocol.BuildExecutePacket("p2", 10),
		protocol.BuildClosePacket('S', "good_stmt"),
		protocol.BuildSyncPacket(),
	}
	for _, p := range safePipeline {
		if _, err := p.WriteTo(client); err != nil {
			t.Fatalf("write safe extended packet: %v", err)
		}
	}

	expectedTypes := []byte{
		protocol.BackendParseComplete,
		protocol.BackendBindComplete,
		protocol.BackendCommandComplete,
		protocol.BackendCloseComplete,
		protocol.BackendReadyForQuery,
	}
	for i, want := range expectedTypes {
		got, err := protocol.ReadPacket(client)
		if err != nil || got.Type != want {
			t.Fatalf("step %d: expected backend packet %c, got err=%v type=%v", i, want, err, got)
		}
	}

	m := srv.GetMetrics()
	if m.ExtendedQueries != 2 || m.BlockedQueries != 1 || m.AllowedQueries != 1 {
		t.Fatalf("unexpected extended metrics: %+v", m)
	}
}

func TestProxyExtendedQueryPipelinedPartialBlock(t *testing.T) {
	mb := startMockPostgresBackend(t, 32)
	defer mb.Close()

	srv, stop := startTestProxy(t, Config{
		TargetAddr: mb.Addr(),
		StrictMode: true,
	})
	defer stop()

	client := dialAndHandshake(t, srv.Addr().String(), nil)
	defer client.Close()

	// Pipeline a SAFE statement and a HAZARDOUS statement before a single Sync
	pkts := []*protocol.Packet{
		protocol.BuildParsePacket("s_ok", "SELECT 1"),
		protocol.BuildBindPacket("p_ok", "s_ok"),
		protocol.BuildExecutePacket("p_ok", 0),
		protocol.BuildParsePacket("s_bad", "VACUUM (FULL) accounts"),
		protocol.BuildBindPacket("p_bad", "s_bad"),
		protocol.BuildExecutePacket("p_bad", 0),
		protocol.BuildSyncPacket(),
	}
	for _, p := range pkts {
		if _, err := p.WriteTo(client); err != nil {
			t.Fatalf("write pipelined packet: %v", err)
		}
	}

	// Expected ordered responses: safe ParseComplete, BindComplete, CommandComplete, then injected ErrorResponse, then ReadyForQuery
	expectedTypes := []byte{
		protocol.BackendParseComplete,
		protocol.BackendBindComplete,
		protocol.BackendCommandComplete,
		protocol.BackendErrorResponse,
		protocol.BackendReadyForQuery,
	}
	for i, want := range expectedTypes {
		got, err := protocol.ReadPacket(client)
		if err != nil || got.Type != want {
			t.Fatalf("pipeline step %d: expected %c, got err=%v pkt=%+v", i, want, err, got)
		}
		if want == protocol.BackendErrorResponse {
			fields, _ := protocol.ParseErrorResponse(got)
			if fields.Code != "55P03" {
				t.Fatalf("expected 55P03 for VACUUM FULL, got %s", fields.Code)
			}
		}
	}

	// Verify connection stays usable afterwards
	resp, _ := sendSimpleQuery(t, client, "SELECT 42;")
	if resp.Type != protocol.BackendCommandComplete {
		t.Fatalf("post-pipeline query failed: %+v", resp)
	}
}

func TestProxySessionLockTimeoutAndPreparedBindTOCTOU(t *testing.T) {
	mb := startMockPostgresBackend(t, 32)
	defer mb.Close()

	srv, stop := startTestProxy(t, Config{
		TargetAddr: mb.Addr(),
		StrictMode: true,
	})
	defer stop()

	client := dialAndHandshake(t, srv.Addr().String(), nil)
	defer client.Close()

	// 1. Open transaction and set local lock_timeout
	resp, tx := sendSimpleQuery(t, client, "BEGIN;")
	if resp.Type != protocol.BackendCommandComplete || tx != protocol.TxInBlock {
		t.Fatalf("expected TxInBlock after BEGIN, got type=%c tx=%c", resp.Type, tx)
	}
	resp, tx = sendSimpleQuery(t, client, "SET LOCAL lock_timeout = '2s';")
	if resp.Type != protocol.BackendCommandComplete || tx != protocol.TxInBlock {
		t.Fatalf("expected SET LOCAL to succeed in tx, got type=%c tx=%c", resp.Type, tx)
	}

	// 2. Prepare ALTER TABLE while lock_timeout IS active (allowed!)
	for _, p := range []*protocol.Packet{
		protocol.BuildParsePacket("ddl_stmt", "ALTER TABLE users ADD COLUMN tag TEXT"),
		protocol.BuildBindPacket("ddl_p1", "ddl_stmt"),
		protocol.BuildExecutePacket("ddl_p1", 0),
		protocol.BuildSyncPacket(),
	} {
		if _, err := p.WriteTo(client); err != nil {
			t.Fatalf("write safe DDL prepared pipeline: %v", err)
		}
	}
	for _, want := range []byte{
		protocol.BackendParseComplete,
		protocol.BackendBindComplete,
		protocol.BackendCommandComplete,
		protocol.BackendReadyForQuery,
	} {
		got, err := protocol.ReadPacket(client)
		if err != nil || got.Type != want {
			t.Fatalf("expected %c for safe DDL prepared stmt, got err=%v pkt=%+v", want, err, got)
		}
	}

	// 3. Verify that blocking a bad query inside an open transaction preserves TxInBlock ('T')
	errPkt, tx := sendSimpleQuery(t, client, "DELETE FROM users;")
	if errPkt.Type != protocol.BackendErrorResponse || tx != protocol.TxInBlock {
		t.Fatalf("expected ErrorResponse preserving TxInBlock ('T'), got type=%c tx=%c", errPkt.Type, tx)
	}

	// 4. COMMIT transaction -> local lock_timeout expires
	resp, tx = sendSimpleQuery(t, client, "COMMIT;")
	if resp.Type != protocol.BackendCommandComplete || tx != protocol.TxIdle {
		t.Fatalf("expected TxIdle after COMMIT, got type=%c tx=%c", resp.Type, tx)
	}

	// 5. Re-executing the previously prepared "ddl_stmt" via Bind/Execute AFTER COMMIT MUST be blocked at Bind!
	for _, p := range []*protocol.Packet{
		protocol.BuildBindPacket("ddl_p2", "ddl_stmt"),
		protocol.BuildExecutePacket("ddl_p2", 0),
		protocol.BuildSyncPacket(),
	} {
		if _, err := p.WriteTo(client); err != nil {
			t.Fatalf("write post-commit Bind/Execute: %v", err)
		}
	}
	bindErr, err := protocol.ReadPacket(client)
	if err != nil || bindErr.Type != protocol.BackendErrorResponse {
		t.Fatalf("expected Bind-time ErrorResponse for expired lock_timeout, got err=%v pkt=%+v", err, bindErr)
	}
	fields, _ := protocol.ParseErrorResponse(bindErr)
	if fields.Code != "55P03" {
		t.Fatalf("expected 55P03 on Bind TOCTOU block, got %s", fields.Code)
	}
	bindReady, err := protocol.ReadPacket(client)
	if err != nil || bindReady.Type != protocol.BackendReadyForQuery {
		t.Fatalf("expected ReadyForQuery after Bind block Sync, got err=%v pkt=%+v", err, bindReady)
	}
}

func TestProxySSLGSSAndCancelHandshake(t *testing.T) {
	mb := startMockPostgresBackend(t, 16)
	defer mb.Close()

	srv, stop := startTestProxy(t, Config{
		TargetAddr: mb.Addr(),
		StrictMode: true,
	})
	defer stop()

	// 1. SSLRequest + GSSENCRequest followed by real StartupMessage
	client, err := net.DialTimeout("tcp", srv.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	if _, err := protocol.BuildSSLRequestPacket().WriteTo(client); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	var reply [1]byte
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply[0] != 'N' {
		t.Fatalf("expected 'N' to SSLRequest, got %q (err=%v)", reply[0], err)
	}

	if _, err := protocol.BuildGSSENCRequestPacket().WriteTo(client); err != nil {
		t.Fatalf("write GSSENCRequest: %v", err)
	}
	if _, err := io.ReadFull(client, reply[:]); err != nil || reply[0] != 'N' {
		t.Fatalf("expected 'N' to GSSENCRequest, got %q (err=%v)", reply[0], err)
	}

	if _, err := protocol.BuildStartupPacket(map[string]string{"user": "ssl_fallback"}).WriteTo(client); err != nil {
		t.Fatalf("write StartupPacket: %v", err)
	}
	if pkt, err := protocol.ReadPacket(client); err != nil || pkt.Type != protocol.BackendAuthentication {
		t.Fatalf("expected AuthenticationOk after SSL/GSS fallback, got err=%v pkt=%+v", err, pkt)
	}
	if pkt, err := protocol.ReadPacket(client); err != nil || pkt.Type != protocol.BackendReadyForQuery {
		t.Fatalf("expected ReadyForQuery after SSL/GSS fallback, got err=%v pkt=%+v", err, pkt)
	}

	// 2. CancelRequest forwarded transparently to backend
	cancelConn, err := net.DialTimeout("tcp", srv.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy for cancel: %v", err)
	}
	defer cancelConn.Close()
	if _, err := protocol.BuildCancelRequestPacket(4242, 9999).WriteTo(cancelConn); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}
	select {
	case pid := <-mb.cancels:
		if pid != 4242 {
			t.Fatalf("expected backend cancel PID 4242, got %d", pid)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("backend never received forwarded CancelRequest")
	}
}

func TestProxyMetricsHTTPEndpointAndLatencyStats(t *testing.T) {
	mb := startMockPostgresBackend(t, 32)
	defer mb.Close()

	srv, stop := startTestProxy(t, Config{
		TargetAddr:  mb.Addr(),
		StrictMode:  true,
		MetricsAddr: "127.0.0.1:0",
	})
	defer stop()

	client := dialAndHandshake(t, srv.Addr().String(), nil)
	defer client.Close()

	for i := 0; i < 5; i++ {
		sendSimpleQuery(t, client, "SELECT 1;")
	}
	sendSimpleQuery(t, client, "DROP DATABASE prod;")

	baseURL := "http://" + srv.MetricsAddr().String()

	healthResp, err := http.Get(baseURL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	defer healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /healthz, got %d", healthResp.StatusCode)
	}

	metricsResp, err := http.Get(baseURL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	defer metricsResp.Body.Close()
	if metricsResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on /metrics, got %d", metricsResp.StatusCode)
	}

	var m Metrics
	if err := json.NewDecoder(metricsResp.Body).Decode(&m); err != nil {
		t.Fatalf("decode /metrics JSON: %v", err)
	}
	if m.TotalQueries != 6 || m.AllowedQueries != 5 || m.BlockedQueries != 1 {
		t.Fatalf("unexpected HTTP metrics snapshot: %+v", m)
	}
	if m.InspectionLatency.Count != 6 || m.BackendLatency.Count != 5 {
		t.Fatalf("unexpected latency counts: inspect=%+v backend=%+v", m.InspectionLatency, m.BackendLatency)
	}
	if m.HazardsByType[gatekeeper.HazardDropDatabaseOrSchema] != 1 {
		t.Fatalf("expected DROP_DATABASE_OR_SCHEMA count=1, got %+v", m.HazardsByType)
	}
}

func TestProxyConcurrentStressRace(t *testing.T) {
	mb := startMockPostgresBackend(t, 2048)
	defer mb.Close()

	var auditBuf bytes.Buffer
	srv, stop := startTestProxy(t, Config{
		TargetAddr:  mb.Addr(),
		StrictMode:  true,
		AuditWriter: &auditBuf,
	})
	defer stop()

	const (
		numClients   = 12
		itersPerConn = 20 // each iter sends 1 safe simple + 1 bad simple + 1 bad extended = 3 queries
	)

	var wg sync.WaitGroup
	errCh := make(chan error, numClients)

	for c := 0; c < numClients; c++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn := dialAndHandshake(t, srv.Addr().String(), map[string]string{"user": "stress"})
			defer conn.Close()

			for i := 0; i < itersPerConn; i++ {
				// 1. Safe simple query
				resp, _ := sendSimpleQuery(t, conn, "SELECT * FROM orders WHERE id = 1;")
				if resp.Type != protocol.BackendCommandComplete {
					errCh <- io.ErrUnexpectedEOF
					return
				}
				// 2. Blocked simple query
				errResp, _ := sendSimpleQuery(t, conn, "DELETE FROM orders;")
				if errResp.Type != protocol.BackendErrorResponse {
					errCh <- io.ErrUnexpectedEOF
					return
				}
				// 3. Blocked extended query
				for _, p := range []*protocol.Packet{
					protocol.BuildParsePacket("s", "CREATE INDEX idx_bad ON orders(id)"),
					protocol.BuildBindPacket("p", "s"),
					protocol.BuildExecutePacket("p", 0),
					protocol.BuildSyncPacket(),
				} {
					if _, err := p.WriteTo(conn); err != nil {
						errCh <- err
						return
					}
				}
				ep, err := protocol.ReadPacket(conn)
				if err != nil || ep.Type != protocol.BackendErrorResponse {
					errCh <- io.ErrUnexpectedEOF
					return
				}
				rp, err := protocol.ReadPacket(conn)
				if err != nil || rp.Type != protocol.BackendReadyForQuery {
					errCh <- io.ErrUnexpectedEOF
					return
				}
			}
			_, _ = protocol.BuildTerminatePacket().WriteTo(conn)
		}(c)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent client failed: %v", err)
	}

	// Wait briefly for server connection teardown to decrement ActiveConnections to 0
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.GetMetrics().ActiveConnections == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	m := srv.GetMetrics()
	wantTotal := uint64(numClients * itersPerConn * 3)
	wantAllowed := uint64(numClients * itersPerConn)
	wantBlocked := uint64(numClients * itersPerConn * 2)
	if m.TotalQueries != wantTotal || m.AllowedQueries != wantAllowed || m.BlockedQueries != wantBlocked {
		t.Fatalf("stress metrics mismatch: got total=%d allowed=%d blocked=%d, want %d/%d/%d",
			m.TotalQueries, m.AllowedQueries, m.BlockedQueries, wantTotal, wantAllowed, wantBlocked)
	}
	if m.ActiveConnections != 0 {
		t.Fatalf("expected 0 active connections after stress test, got %d", m.ActiveConnections)
	}

	// Verify every NDJSON audit line parses cleanly without interleaving
	scanner := bufio.NewScanner(&auditBuf)
	lines := 0
	for scanner.Scan() {
		var ev AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("corrupted NDJSON audit line %d: %v", lines+1, err)
		}
		lines++
	}
	if uint64(lines) != wantTotal {
		t.Fatalf("expected %d audit NDJSON lines, got %d", wantTotal, lines)
	}
}
