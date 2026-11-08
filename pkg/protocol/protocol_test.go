package protocol

import (
	"bytes"
	"testing"
)

func TestReadWritePacket(t *testing.T) {
	pkt := BuildErrorResponse("ERROR", "55P03", "lock timeout hazard detected", "table lock without lock_timeout")
	var buf bytes.Buffer
	if err := pkt.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}

	readPkt, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket failed: %v", err)
	}

	if readPkt.Type != BackendErrorResponse {
		t.Fatalf("expected packet type %c, got %c", BackendErrorResponse, readPkt.Type)
	}
	if readPkt.Length != pkt.Length {
		t.Fatalf("expected length %d, got %d", pkt.Length, readPkt.Length)
	}
	if !bytes.Equal(readPkt.Payload, pkt.Payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestExtractQuerySimple(t *testing.T) {
	sql := "SELECT * FROM users WHERE id = 1"
	payload := append([]byte(sql), 0)
	pkt := &Packet{
		Type:    MsgQuery,
		Length:  int32(len(payload) + 4),
		Payload: payload,
	}

	q, err := pkt.ExtractQuery()
	if err != nil {
		t.Fatalf("ExtractQuery failed: %v", err)
	}
	if q != sql {
		t.Fatalf("expected %q, got %q", sql, q)
	}
}

func TestExtractQueryParse(t *testing.T) {
	stmt := "stmt_user_lookup"
	sql := "UPDATE accounts SET balance = balance - 100 WHERE id = $1"
	var payload []byte
	payload = append(payload, []byte(stmt)...)
	payload = append(payload, 0)
	payload = append(payload, []byte(sql)...)
	payload = append(payload, 0)
	payload = append(payload, 0, 0) // 0 parameter OIDs

	pkt := &Packet{
		Type:    MsgParse,
		Length:  int32(len(payload) + 4),
		Payload: payload,
	}

	q, err := pkt.ExtractQuery()
	if err != nil {
		t.Fatalf("ExtractQuery parse failed: %v", err)
	}
	if q != sql {
		t.Fatalf("expected %q, got %q", sql, q)
	}
}

func TestBuildReadyForQuery(t *testing.T) {
	pkt := BuildReadyForQuery('I')
	if pkt.Type != BackendReadyForQuery || pkt.Length != 5 || len(pkt.Payload) != 1 || pkt.Payload[0] != 'I' {
		t.Fatalf("malformed ReadyForQuery: %+v", pkt)
	}
}
