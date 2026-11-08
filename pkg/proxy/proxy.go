package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Aetherx86/Pyx/pkg/gatekeeper"
	"github.com/Aetherx86/Pyx/pkg/protocol"
)

type Config struct {
	ListenAddr string
	TargetAddr string
	StrictMode bool
	Verbose    bool
}

type Metrics struct {
	TotalConnections uint64
	TotalQueries     uint64
	BlockedQueries   uint64
	HazardsDetected  uint64
}

type Server struct {
	cfg        Config
	gk         *gatekeeper.Gatekeeper
	listener   net.Listener
	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	metrics    Metrics
	shutdownCh chan struct{}
}

func NewServer(cfg Config) *Server {
	return &Server{
		cfg:        cfg,
		gk:         gatekeeper.New(cfg.StrictMode),
		conns:      make(map[net.Conn]struct{}),
		shutdownCh: make(chan struct{}),
	}
}

func (s *Server) GetMetrics() Metrics {
	return Metrics{
		TotalConnections: atomic.LoadUint64(&s.metrics.TotalConnections),
		TotalQueries:     atomic.LoadUint64(&s.metrics.TotalQueries),
		BlockedQueries:   atomic.LoadUint64(&s.metrics.BlockedQueries),
		HazardsDetected:  atomic.LoadUint64(&s.metrics.HazardsDetected),
	}
}

// Start launches the TCP wire proxy listener.
func (s *Server) Start(ctx context.Context) error {
	l, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind proxy listener: %w", err)
	}
	s.listener = l

	go func() {
		<-ctx.Done()
		s.Close()
	}()

	for {
		clientConn, err := l.Accept()
		if err != nil {
			select {
			case <-s.shutdownCh:
				return nil
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}

		atomic.AddUint64(&s.metrics.TotalConnections, 1)
		s.trackConn(clientConn, true)

		go s.handleConnection(clientConn)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	select {
	case <-s.shutdownCh:
		return nil
	default:
		close(s.shutdownCh)
	}

	if s.listener != nil {
		_ = s.listener.Close()
	}

	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = make(map[net.Conn]struct{})
	return nil
}

func (s *Server) trackConn(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
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
		// Write error response packet to client and close
		errPkt := protocol.BuildErrorResponse("FATAL", "08001", "Pyx proxy cannot connect to postgres target", err.Error())
		_ = errPkt.WriteTo(client)
		return
	}
	defer backend.Close()
	s.trackConn(backend, true)
	defer s.trackConn(backend, false)

	// Step 1: Handle initial connection / SSL handshake negotiation
	if err := s.handleHandshake(client, backend); err != nil {
		return
	}

	// Step 2: Pump backend responses to client concurrently
	errCh := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(client, backend)
		errCh <- copyErr
	}()

	// Step 3: Intercept client-to-backend queries
	go func() {
		errCh <- s.pumpClientToBackend(client, backend)
	}()

	<-errCh
}

func (s *Server) handleHandshake(client, backend net.Conn) error {
	startupPkt, err := protocol.ReadStartupPacket(client)
	if err != nil {
		return err
	}

	// Check if this is an SSL negotiation request (Code 80877103)
	if len(startupPkt.Payload) >= 4 {
		code := int32(uint32(startupPkt.Payload[0])<<24 | uint32(startupPkt.Payload[1])<<16 | uint32(startupPkt.Payload[2])<<8 | uint32(startupPkt.Payload[3]))
		if code == protocol.SSLRequestCode {
			// Transparently reply with 'N' (SSL not supported directly at proxy level, or forward if target requires)
			if _, err := client.Write([]byte{'N'}); err != nil {
				return err
			}
			// Re-read the real startup message
			startupPkt, err = protocol.ReadStartupPacket(client)
			if err != nil {
				return err
			}
		}
	}

	// Forward startup packet to PostgreSQL backend
	return startupPkt.WriteTo(backend)
}

func (s *Server) pumpClientToBackend(client, backend net.Conn) error {
	for {
		pkt, err := protocol.ReadPacket(client)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		if pkt.Type == protocol.MsgQuery || pkt.Type == protocol.MsgParse {
			atomic.AddUint64(&s.metrics.TotalQueries, 1)
			query, err := pkt.ExtractQuery()
			if err == nil && query != "" {
				hazards := s.gk.Inspect(query)
				if len(hazards) > 0 {
					atomic.AddUint64(&s.metrics.HazardsDetected, uint64(len(hazards)))
					if s.cfg.Verbose {
						log.Printf("[pyx-alert] Query hazard intercepted from %s:\n%s\nSQL: %s",
							client.RemoteAddr(), gatekeeper.FormatHazards(hazards), query)
					}

					block, h := s.gk.ShouldBlock(hazards)
					if block {
						atomic.AddUint64(&s.metrics.BlockedQueries, 1)
						if s.cfg.Verbose {
							log.Printf("[pyx-blocked] Strict mode active: returning SQLSTATE %s to client", h.SQLState)
						}

						// Synthesize wire-level ErrorResponse ('E') and ReadyForQuery ('Z')
						errPkt := protocol.BuildErrorResponse(string(h.Severity), h.SQLState, h.Message, h.Detail)
						readyPkt := protocol.BuildReadyForQuery('I')

						if writeErr := errPkt.WriteTo(client); writeErr != nil {
							return writeErr
						}
						if writeErr := readyPkt.WriteTo(client); writeErr != nil {
							return writeErr
						}

						// Do NOT forward packet to backend; continue reading next client query
						continue
					}
				}
			}
		}

		// Forward packet to backend
		if writeErr := pkt.WriteTo(backend); writeErr != nil {
			return writeErr
		}
	}
}
