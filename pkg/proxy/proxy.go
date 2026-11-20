package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Aetherx86/Pyx/pkg/gatekeeper"
	"github.com/Aetherx86/Pyx/pkg/protocol"
)

type Config struct {
	ListenAddr  string
	TargetAddr  string
	StrictMode  bool
	Policy      *gatekeeper.Policy
	Verbose     bool
	AuditWriter io.Writer
	MetricsAddr string
}

type Server struct {
	cfg       Config
	gk        *gatekeeper.Gatekeeper
	collector *metricsCollector
	audit     *auditLogger

	mu              sync.Mutex
	listener        net.Listener
	metricsListener net.Listener
	metricsServer   *http.Server
	conns           map[net.Conn]struct{}
	closed          bool

	readyOnce  sync.Once
	readyCh    chan struct{}
	shutdownCh chan struct{}
	connWG     sync.WaitGroup
}

func NewServer(cfg Config) *Server {
	pol := gatekeeper.DefaultPolicy(cfg.StrictMode)
	if cfg.Policy != nil {
		pol = *cfg.Policy
	}
	return &Server{
		cfg:        cfg,
		gk:         gatekeeper.NewWithPolicy(pol),
		collector:  newMetricsCollector(pol.StrictMode),
		audit:      newAuditLogger(cfg.AuditWriter),
		conns:      make(map[net.Conn]struct{}),
		readyCh:    make(chan struct{}),
		shutdownCh: make(chan struct{}),
	}
}

// GetMetrics returns a thread-safe snapshot of proxy telemetry and latency statistics.
func (s *Server) GetMetrics() Metrics {
	return s.collector.Snapshot()
}

// Ready returns a channel that is closed once the TCP listener (and optional metrics server) is bound.
func (s *Server) Ready() <-chan struct{} {
	return s.readyCh
}

// Addr returns the bound proxy TCP listener address, or nil if not started.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// MetricsAddr returns the bound HTTP metrics listener address, or nil if disabled/not started.
func (s *Server) MetricsAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.metricsListener == nil {
		return nil
	}
	return s.metricsListener.Addr()
}

// Start launches the TCP wire proxy listener and optional HTTP metrics endpoint.
func (s *Server) Start(ctx context.Context) error {
	l, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind proxy listener: %w", err)
	}

	var ml net.Listener
	var msrv *http.Server
	if s.cfg.MetricsAddr != "" {
		ml, err = net.Listen("tcp", s.cfg.MetricsAddr)
		if err != nil {
			_ = l.Close()
			return fmt.Errorf("failed to bind metrics listener: %w", err)
		}
		msrv = s.buildMetricsHTTPServer()
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = l.Close()
		if ml != nil {
			_ = ml.Close()
		}
		return nil
	}
	s.listener = l
	s.metricsListener = ml
	s.metricsServer = msrv
	s.mu.Unlock()

	if msrv != nil && ml != nil {
		go func() {
			if serveErr := msrv.Serve(ml); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				if s.cfg.Verbose {
					log.Printf("[pyx] metrics HTTP server error: %v", serveErr)
				}
			}
		}()
	}

	s.readyOnce.Do(func() { close(s.readyCh) })

	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.shutdownCh:
		}
	}()

	for {
		clientConn, err := l.Accept()
		if err != nil {
			select {
			case <-s.shutdownCh:
				s.connWG.Wait()
				return nil
			case <-ctx.Done():
				s.connWG.Wait()
				return nil
			default:
				s.connWG.Wait()
				return err
			}
		}

		s.collector.totalConnections.Add(1)
		s.collector.activeConnections.Add(1)
		s.trackConn(clientConn, true)

		s.connWG.Add(1)
		go func(c net.Conn) {
			defer s.connWG.Done()
			defer s.collector.activeConnections.Add(-1)
			s.handleConnection(c)
		}(clientConn)
	}
}

func (s *Server) buildMetricsHTTPServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		snap := s.GetMetrics()
		data, err := snap.MarshalJSONReport()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		_, _ = w.Write([]byte("\n"))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		snap := s.GetMetrics()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":             "ok",
			"mode":               snap.Mode,
			"active_connections": snap.ActiveConnections,
			"total_queries":      snap.TotalQueries,
			"blocked_queries":    snap.BlockedQueries,
		})
	})
	return &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.shutdownCh)

	l := s.listener
	msrv := s.metricsServer
	ml := s.metricsListener
	conns := s.conns
	s.conns = make(map[net.Conn]struct{})
	s.mu.Unlock()

	if l != nil {
		_ = l.Close()
	}
	if msrv != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = msrv.Shutdown(shutCtx)
		cancel()
	} else if ml != nil {
		_ = ml.Close()
	}
	for c := range conns {
		_ = c.Close()
	}
	return nil
}

func (s *Server) trackConn(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		if add {
			_ = c.Close()
		}
		return
	}
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

type pendingQuery struct {
	startedAt   time.Time
	prevSession *gatekeeper.SessionState
	hadError    bool
	deferredErr *gatekeeper.Hazard
}

type connSession struct {
	clientAddr string
	user       string
	database   string
	appName    string

	clientWriteMu sync.Mutex

	stateMu       sync.Mutex
	txStatus      byte
	sqlSession    *gatekeeper.SessionState
	preparedStmts map[string]string
	portals       map[string]string

	pendingMu    sync.Mutex
	pendingQueue []pendingQuery

	// Accessed solely by pumpClientToBackend
	skipUntilSync     bool
	extendedForwarded bool
	deferredErr       *gatekeeper.Hazard
	batchPrevSession  *gatekeeper.SessionState
}

func newConnSession(clientAddr string) *connSession {
	return &connSession{
		clientAddr:    clientAddr,
		txStatus:      protocol.TxIdle,
		sqlSession:    gatekeeper.NewSessionState(),
		preparedStmts: make(map[string]string),
		portals:       make(map[string]string),
	}
}

func (cs *connSession) getTxStatus() byte {
	cs.stateMu.Lock()
	st := cs.txStatus
	cs.stateMu.Unlock()
	if st == 0 {
		return protocol.TxIdle
	}
	return st
}

func (cs *connSession) writeClientPackets(client net.Conn, pkts ...*protocol.Packet) error {
	cs.clientWriteMu.Lock()
	defer cs.clientWriteMu.Unlock()
	for _, p := range pkts {
		if _, err := p.WriteTo(client); err != nil {
			return err
		}
	}
	return nil
}

func (cs *connSession) enqueuePending(pq pendingQuery) {
	cs.pendingMu.Lock()
	cs.pendingQueue = append(cs.pendingQueue, pq)
	cs.pendingMu.Unlock()
}

func (cs *connSession) markHeadPendingError() {
	cs.pendingMu.Lock()
	if len(cs.pendingQueue) > 0 {
		cs.pendingQueue[0].hadError = true
	}
	cs.pendingMu.Unlock()
}

func (cs *connSession) popPending() (pendingQuery, bool) {
	cs.pendingMu.Lock()
	defer cs.pendingMu.Unlock()
	if len(cs.pendingQueue) == 0 {
		return pendingQuery{}, false
	}
	head := cs.pendingQueue[0]
	cs.pendingQueue = cs.pendingQueue[1:]
	return head, true
}

func (s *Server) handleConnection(client net.Conn) {
	defer func() {
		_ = client.Close()
		s.trackConn(client, false)
	}()

	backend, err := net.DialTimeout("tcp", s.cfg.TargetAddr, 5*time.Second)
	if err != nil {
		if s.cfg.Verbose {
			log.Printf("[pyx] failed to connect to postgres backend at %s: %v", s.cfg.TargetAddr, err)
		}
		errPkt := protocol.BuildErrorResponse("FATAL", "08001", "Pyx proxy cannot connect to postgres target", err.Error())
		_, _ = errPkt.WriteTo(client)
		return
	}
	defer backend.Close()
	s.trackConn(backend, true)
	defer s.trackConn(backend, false)

	sess := newConnSession(client.RemoteAddr().String())
	clientReader := bufio.NewReaderSize(client, 16*1024)
	backendReader := bufio.NewReaderSize(backend, 16*1024)

	// Step 1: Handle initial connection / SSL / GSSENC / CancelRequest negotiation
	isCancel, err := s.handleHandshake(clientReader, client, backend, sess)
	if err != nil || isCancel {
		return
	}

	// Step 2: Bidirectional framed pumping with serialized client writes
	errCh := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		errCh <- s.pumpBackendToClient(backendReader, client, sess)
	}()

	go func() {
		defer wg.Done()
		errCh <- s.pumpClientToBackend(clientReader, client, backend, sess)
	}()

	<-errCh
	_ = client.Close()
	_ = backend.Close()
	wg.Wait()
}

func (s *Server) handleHandshake(clientReader io.Reader, client, backend net.Conn, sess *connSession) (isCancel bool, err error) {
	for attempt := 0; attempt < 4; attempt++ {
		startupPkt, err := protocol.ReadStartupPacket(clientReader)
		if err != nil {
			return false, err
		}

		if code, ok := protocol.StartupCode(startupPkt); ok {
			switch code {
			case protocol.SSLRequestCode, protocol.GSSENCRequestCode:
				if _, err := client.Write([]byte{'N'}); err != nil {
					return false, err
				}
				continue

			case protocol.CancelRequestCode:
				_, err := startupPkt.WriteTo(backend)
				return true, err
			}
		}

		params := protocol.ParseStartupParams(startupPkt)
		sess.user = params["user"]
		sess.database = params["database"]
		sess.appName = params["application_name"]

		_, err = startupPkt.WriteTo(backend)
		return false, err
	}
	return false, errors.New("too many startup negotiation requests")
}

func (s *Server) pumpBackendToClient(backendReader io.Reader, client net.Conn, sess *connSession) error {
	for {
		pkt, err := protocol.ReadPacket(backendReader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		if pkt.Type == protocol.BackendErrorResponse {
			sess.markHeadPendingError()
		}

		if pkt.Type == protocol.BackendReadyForQuery {
			txStatus, statusErr := pkt.ExtractReadyForQuery()
			pq, hasPending := sess.popPending()
			if hasPending {
				s.collector.backendLatency.Observe(time.Since(pq.startedAt))
			}

			sess.stateMu.Lock()
			if hasPending && pq.hadError && pq.prevSession != nil {
				sess.sqlSession = pq.prevSession
			}
			if statusErr == nil {
				sess.txStatus = txStatus
				switch txStatus {
				case protocol.TxIdle:
					sess.sqlSession.InTransaction = false
					sess.sqlSession.ResetLocal()
				case protocol.TxInBlock:
					sess.sqlSession.InTransaction = true
				case protocol.TxFailed:
					sess.sqlSession.InTransaction = true
				}
			}
			sess.stateMu.Unlock()

			if hasPending && pq.deferredErr != nil {
				h := pq.deferredErr
				errPkt := protocol.BuildErrorResponse(h.WireSeverity(), h.SQLState, h.Message, h.Detail)
				if writeErr := sess.writeClientPackets(client, errPkt, pkt); writeErr != nil {
					return writeErr
				}
				continue
			}
		}

		if writeErr := sess.writeClientPackets(client, pkt); writeErr != nil {
			return writeErr
		}
	}
}

func (s *Server) pumpClientToBackend(clientReader io.Reader, client, backend net.Conn, sess *connSession) error {
	for {
		pkt, err := protocol.ReadPacket(clientReader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		switch pkt.Type {
		case protocol.MsgQuery:
			// Simple query resets any stale extended-query skip state.
			sess.skipUntilSync = false
			sess.extendedForwarded = false
			sess.deferredErr = nil
			sess.batchPrevSession = nil

			s.collector.totalQueries.Add(1)
			s.collector.simpleQueries.Add(1)

			query, qErr := pkt.ExtractQuery()
			if qErr == nil && query != "" {
				sess.stateMu.Lock()
				snap := sess.sqlSession.Clone()
				sess.stateMu.Unlock()

				t0 := time.Now()
				hazards := s.gk.InspectWithSession(query, snap)
				inspectDur := time.Since(t0)
				s.collector.inspectionLatency.Observe(inspectDur)

				if len(hazards) > 0 {
					s.collector.RecordHazards(hazards)
					if s.cfg.Verbose {
						log.Printf("[pyx-alert] Query hazard intercepted from %s:\n%s\nSQL: %s",
							sess.clientAddr, gatekeeper.FormatHazards(hazards), query)
					}

					block, h := s.gk.ShouldBlock(hazards)
					if block {
						s.collector.blockedQueries.Add(1)
						s.emitAudit(sess, "Query", "", "BLOCK", inspectDur, query, hazards)
						if s.cfg.Verbose {
							log.Printf("[pyx-blocked] Strict mode active: returning SQLSTATE %s to client", h.SQLState)
						}

						errPkt := protocol.BuildErrorResponse(h.WireSeverity(), h.SQLState, h.Message, h.Detail)
						readyPkt := protocol.BuildReadyForQuery(sess.getTxStatus())
						if writeErr := sess.writeClientPackets(client, errPkt, readyPkt); writeErr != nil {
							return writeErr
						}
						continue
					}

					s.collector.allowedQueries.Add(1)
					s.collector.auditAlertQueries.Add(1)
					s.emitAudit(sess, "Query", "", "AUDIT", inspectDur, query, hazards)
				} else {
					s.collector.allowedQueries.Add(1)
					s.emitAudit(sess, "Query", "", "ALLOW", inspectDur, query, nil)
				}

				sess.stateMu.Lock()
				prev := sess.sqlSession.Clone()
				sess.sqlSession.ApplySQL(query)
				sess.stateMu.Unlock()
				sess.enqueuePending(pendingQuery{startedAt: time.Now(), prevSession: prev})
			} else {
				sess.enqueuePending(pendingQuery{startedAt: time.Now()})
			}

			if _, writeErr := pkt.WriteTo(backend); writeErr != nil {
				return writeErr
			}

		case protocol.MsgParse:
			if sess.skipUntilSync {
				continue
			}

			s.collector.totalQueries.Add(1)
			s.collector.extendedQueries.Add(1)

			stmtName, query, _, pErr := pkt.ExtractParse()
			if pErr == nil && query != "" {
				sess.stateMu.Lock()
				snap := sess.sqlSession.Clone()
				sess.stateMu.Unlock()

				t0 := time.Now()
				hazards := s.gk.InspectWithSession(query, snap)
				inspectDur := time.Since(t0)
				s.collector.inspectionLatency.Observe(inspectDur)

				if len(hazards) > 0 {
					s.collector.RecordHazards(hazards)
					if s.cfg.Verbose {
						log.Printf("[pyx-alert] Parse(%q) hazard intercepted from %s:\n%s\nSQL: %s",
							stmtName, sess.clientAddr, gatekeeper.FormatHazards(hazards), query)
					}

					block, h := s.gk.ShouldBlock(hazards)
					if block {
						s.collector.blockedQueries.Add(1)
						s.emitAudit(sess, "Parse", stmtName, "BLOCK", inspectDur, query, hazards)
						sess.skipUntilSync = true
						if !sess.extendedForwarded {
							errPkt := protocol.BuildErrorResponse(h.WireSeverity(), h.SQLState, h.Message, h.Detail)
							if writeErr := sess.writeClientPackets(client, errPkt); writeErr != nil {
								return writeErr
							}
						} else {
							hCopy := h
							sess.deferredErr = &hCopy
						}
						continue
					}

					s.collector.allowedQueries.Add(1)
					s.collector.auditAlertQueries.Add(1)
					s.emitAudit(sess, "Parse", stmtName, "AUDIT", inspectDur, query, hazards)
				} else {
					s.collector.allowedQueries.Add(1)
					s.emitAudit(sess, "Parse", stmtName, "ALLOW", inspectDur, query, nil)
				}

				sess.stateMu.Lock()
				sess.preparedStmts[stmtName] = query
				sess.stateMu.Unlock()
			}

			sess.extendedForwarded = true
			if _, writeErr := pkt.WriteTo(backend); writeErr != nil {
				return writeErr
			}

		case protocol.MsgBind:
			if sess.skipUntilSync {
				continue
			}

			if portalName, stmtName, bErr := pkt.ExtractBind(); bErr == nil {
				sess.stateMu.Lock()
				sql, known := sess.preparedStmts[stmtName]
				snap := sess.sqlSession.Clone()
				sess.stateMu.Unlock()

				if known && sql != "" {
					t0 := time.Now()
					hazards := s.gk.InspectWithSession(sql, snap)
					inspectDur := time.Since(t0)
					s.collector.inspectionLatency.Observe(inspectDur)

					if len(hazards) > 0 {
						if block, h := s.gk.ShouldBlock(hazards); block {
							s.collector.RecordHazards(hazards)
							s.collector.blockedQueries.Add(1)
							s.emitAudit(sess, "Bind", stmtName, "BLOCK", inspectDur, sql, hazards)
							sess.skipUntilSync = true
							if !sess.extendedForwarded {
								errPkt := protocol.BuildErrorResponse(h.WireSeverity(), h.SQLState, h.Message, h.Detail)
								if writeErr := sess.writeClientPackets(client, errPkt); writeErr != nil {
									return writeErr
								}
							} else {
								hCopy := h
								sess.deferredErr = &hCopy
							}
							continue
						}
					}
				}

				sess.stateMu.Lock()
				sess.portals[portalName] = stmtName
				sess.stateMu.Unlock()
			}

			sess.extendedForwarded = true
			if _, writeErr := pkt.WriteTo(backend); writeErr != nil {
				return writeErr
			}

		case protocol.MsgExecute:
			if sess.skipUntilSync {
				continue
			}

			if portalName, _, eErr := pkt.ExtractExecute(); eErr == nil {
				sess.stateMu.Lock()
				if stmtName, ok := sess.portals[portalName]; ok {
					if sql, ok := sess.preparedStmts[stmtName]; ok && sql != "" {
						if sess.batchPrevSession == nil {
							sess.batchPrevSession = sess.sqlSession.Clone()
						}
						sess.sqlSession.ApplySQL(sql)
					}
				}
				sess.stateMu.Unlock()
			}

			sess.extendedForwarded = true
			if _, writeErr := pkt.WriteTo(backend); writeErr != nil {
				return writeErr
			}

		case protocol.MsgDescribe, protocol.MsgFlush:
			if sess.skipUntilSync {
				continue
			}
			sess.extendedForwarded = true
			if _, writeErr := pkt.WriteTo(backend); writeErr != nil {
				return writeErr
			}

		case protocol.MsgClose:
			if sess.skipUntilSync {
				continue
			}
			if targetType, name, cErr := pkt.ExtractClose(); cErr == nil {
				sess.stateMu.Lock()
				if targetType == 'S' {
					delete(sess.preparedStmts, name)
				} else if targetType == 'P' {
					delete(sess.portals, name)
				}
				sess.stateMu.Unlock()
			}
			sess.extendedForwarded = true
			if _, writeErr := pkt.WriteTo(backend); writeErr != nil {
				return writeErr
			}

		case protocol.MsgSync:
			if sess.skipUntilSync {
				sess.skipUntilSync = false
				if !sess.extendedForwarded {
					readyPkt := protocol.BuildReadyForQuery(sess.getTxStatus())
					if writeErr := sess.writeClientPackets(client, readyPkt); writeErr != nil {
						return writeErr
					}
					continue
				}
				deferred := sess.deferredErr
				sess.deferredErr = nil
				sess.extendedForwarded = false
				prev := sess.batchPrevSession
				sess.batchPrevSession = nil
				sess.enqueuePending(pendingQuery{
					startedAt:   time.Now(),
					prevSession: prev,
					deferredErr: deferred,
				})
				if _, writeErr := pkt.WriteTo(backend); writeErr != nil {
					return writeErr
				}
				continue
			}

			sess.extendedForwarded = false
			prev := sess.batchPrevSession
			sess.batchPrevSession = nil
			sess.enqueuePending(pendingQuery{
				startedAt:   time.Now(),
				prevSession: prev,
			})
			if _, writeErr := pkt.WriteTo(backend); writeErr != nil {
				return writeErr
			}

		default:
			if _, writeErr := pkt.WriteTo(backend); writeErr != nil {
				return writeErr
			}
		}
	}
}

func (s *Server) emitAudit(sess *connSession, protoMsg, stmtName, decision string, inspectDur time.Duration, sql string, hazards []gatekeeper.Hazard) {
	if s.audit == nil {
		return
	}
	s.audit.Log(AuditEvent{
		Timestamp:     time.Now().UTC(),
		ClientAddr:    sess.clientAddr,
		User:          sess.user,
		Database:      sess.database,
		ProtocolMsg:   protoMsg,
		StatementName: stmtName,
		Decision:      decision,
		InspectionUS:  roundUS(float64(inspectDur.Nanoseconds()) / 1000.0),
		SQL:           sql,
		Hazards:       hazards,
	})
}
