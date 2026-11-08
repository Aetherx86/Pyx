package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/Aetherx86/Pyx/pkg/protocol"
)

// mockPostgresBackend simulates a minimal PostgreSQL server responding to startup and queries.
func mockPostgresBackend(t *testing.T, addr string, receivedQueries chan<- string) net.Listener {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("failed to bind mock backend: %v", err)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read startup packet
				_, err := protocol.ReadStartupPacket(c)
				if err != nil {
					return
				}
				// Reply with AuthenticationOk ('R', len 8, type 0)
				var authOk [9]byte
				authOk[0] = 'R'
				binary.BigEndian.PutUint32(authOk[1:5], 8)
				binary.BigEndian.PutUint32(authOk[5:9], 0)
				_, _ = c.Write(authOk[:])

				// Reply with ReadyForQuery ('Z')
				ready := protocol.BuildReadyForQuery('I')
				_ = ready.WriteTo(c)

				for {
					pkt, err := protocol.ReadPacket(c)
					if err != nil {
						return
					}
					if pkt.Type == protocol.MsgQuery {
						q, _ := pkt.ExtractQuery()
						receivedQueries <- q
						// Reply with CommandComplete ('C') and ReadyForQuery ('Z')
						tag := append([]byte("SELECT 1"), 0)
						cmdPkt := &protocol.Packet{
							Type:    protocol.BackendCommandComplete,
							Length:  int32(len(tag) + 4),
							Payload: tag,
						}
						_ = cmdPkt.WriteTo(c)
						_ = ready.WriteTo(c)
					}
				}
			}(conn)
		}
	}()

	return l
}

func TestProxyStrictBlocking(t *testing.T) {
	backendAddr := "127.0.0.1:25432"
	proxyAddr := "127.0.0.1:25433"
	received := make(chan string, 10)

	backendListener := mockPostgresBackend(t, backendAddr, received)
	defer backendListener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := NewServer(Config{
		ListenAddr: proxyAddr,
		TargetAddr: backendAddr,
		StrictMode: true,
		Verbose:    false,
	})

	go func() {
		_ = srv.Start(ctx)
	}()
	time.Sleep(50 * time.Millisecond)

	// Connect mock client
	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer client.Close()

	// Send startup packet
	var startupBuf bytes.Buffer
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 8)
	startupBuf.Write(lenBuf[:])
	var verBuf [4]byte
	binary.BigEndian.PutUint32(verBuf[:], protocol.ProtocolVersion3)
	startupBuf.Write(verBuf[:])
	if _, err := client.Write(startupBuf.Bytes()); err != nil {
		t.Fatalf("failed to send startup packet: %v", err)
	}

	// Read AuthenticationOk and ReadyForQuery
	_, err = protocol.ReadPacket(client)
	if err != nil {
		t.Fatalf("failed to read auth response: %v", err)
	}
	_, err = protocol.ReadPacket(client)
	if err != nil {
		t.Fatalf("failed to read ready response: %v", err)
	}

	// 1. Send safe query
	safeSQL := "SELECT 1;"
	safePkt := &protocol.Packet{
		Type:    protocol.MsgQuery,
		Length:  int32(len(safeSQL) + 5),
		Payload: append([]byte(safeSQL), 0),
	}
	if err := safePkt.WriteTo(client); err != nil {
		t.Fatalf("failed to write safe query: %v", err)
	}

	// Client should get CommandComplete & ReadyForQuery
	reply1, err := protocol.ReadPacket(client)
	if err != nil || reply1.Type != protocol.BackendCommandComplete {
		t.Fatalf("expected CommandComplete, got %v (%c)", err, reply1.Type)
	}
	reply2, err := protocol.ReadPacket(client)
	if err != nil || reply2.Type != protocol.BackendReadyForQuery {
		t.Fatalf("expected ReadyForQuery, got %v (%c)", err, reply2.Type)
	}

	select {
	case q := <-received:
		if q != safeSQL {
			t.Fatalf("backend got %q, expected %q", q, safeSQL)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("backend timed out waiting for safe query")
	}

	// 2. Send dangerous unconstrained ALTER TABLE in Strict Mode
	badSQL := "ALTER TABLE customers ADD COLUMN balance INT;"
	badPkt := &protocol.Packet{
		Type:    protocol.MsgQuery,
		Length:  int32(len(badSQL) + 5),
		Payload: append([]byte(badSQL), 0),
	}
	if err := badPkt.WriteTo(client); err != nil {
		t.Fatalf("failed to write bad query: %v", err)
	}

	// Client should immediately receive synthetic ErrorResponse ('E') and ReadyForQuery ('Z')
	errReply, err := protocol.ReadPacket(client)
	if err != nil || errReply.Type != protocol.BackendErrorResponse {
		t.Fatalf("expected ErrorResponse from proxy, got %v (%c)", err, errReply.Type)
	}
	readyReply, err := protocol.ReadPacket(client)
	if err != nil || readyReply.Type != protocol.BackendReadyForQuery {
		t.Fatalf("expected ReadyForQuery from proxy, got %v (%c)", err, readyReply.Type)
	}

	// Backend MUST NOT have received the bad query
	select {
	case q := <-received:
		t.Fatalf("backend received forbidden query %q!", q)
	case <-time.After(100 * time.Millisecond):
		// Expected: nothing sent to backend
	}

	metrics := srv.GetMetrics()
	if metrics.BlockedQueries != 1 {
		t.Fatalf("expected 1 blocked query in metrics, got %d", metrics.BlockedQueries)
	}
}
