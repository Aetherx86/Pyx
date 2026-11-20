package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// Compile-time verification that *Packet satisfies io.WriterTo.
var _ io.WriterTo = (*Packet)(nil)

func TestReadWritePacket(t *testing.T) {
	pkt := BuildErrorResponse("ERROR", "55P03", "lock timeout hazard detected", "table lock without lock_timeout")
	var buf bytes.Buffer
	written, err := pkt.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if written != int64(buf.Len()) {
		t.Fatalf("expected WriteTo byte count %d, got %d", buf.Len(), written)
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

	fields, err := ParseErrorResponse(readPkt)
	if err != nil {
		t.Fatalf("ParseErrorResponse failed: %v", err)
	}
	if fields.Severity != "ERROR" || fields.Code != "55P03" || fields.Message != "lock timeout hazard detected" || fields.Detail != "table lock without lock_timeout" {
		t.Fatalf("unexpected decoded ErrorFields: %+v", fields)
	}
	if fields.Routine != "PyxGatekeeperEnforce" {
		t.Fatalf("expected routine PyxGatekeeperEnforce, got %q", fields.Routine)
	}
}

func TestReadWriteLargePacket(t *testing.T) {
	// Exceeds the 4096-byte stack fast-path buffer in WriteTo
	largeSQL := "SELECT '" + string(bytes.Repeat([]byte("a"), 6000)) + "'"
	pkt := BuildQueryPacket(largeSQL)
	var buf bytes.Buffer
	written, err := pkt.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo large packet failed: %v", err)
	}
	if written != int64(buf.Len()) {
		t.Fatalf("written count mismatch: %d != %d", written, buf.Len())
	}
	got, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket large packet failed: %v", err)
	}
	q, err := got.ExtractQuery()
	if err != nil || q != largeSQL {
		t.Fatalf("large query mismatch: err=%v, len=%d", err, len(q))
	}
}

func TestStartupPacketsAndParams(t *testing.T) {
	ssl := BuildSSLRequestPacket()
	var buf bytes.Buffer
	if _, err := ssl.WriteTo(&buf); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	gotSSL, err := ReadStartupPacket(&buf)
	if err != nil {
		t.Fatalf("read SSLRequest: %v", err)
	}
	code, ok := StartupCode(gotSSL)
	if !ok || code != SSLRequestCode {
		t.Fatalf("expected SSLRequestCode %d, got %d (ok=%v)", SSLRequestCode, code, ok)
	}

	gss := BuildGSSENCRequestPacket()
	buf.Reset()
	if _, err := gss.WriteTo(&buf); err != nil {
		t.Fatalf("write GSSENCRequest: %v", err)
	}
	gotGSS, err := ReadStartupPacket(&buf)
	if err != nil {
		t.Fatalf("read GSSENCRequest: %v", err)
	}
	if code, ok := StartupCode(gotGSS); !ok || code != GSSENCRequestCode {
		t.Fatalf("expected GSSENCRequestCode, got %d", code)
	}

	cancel := BuildCancelRequestPacket(1234, 56789)
	buf.Reset()
	if _, err := cancel.WriteTo(&buf); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}
	gotCancel, err := ReadStartupPacket(&buf)
	if err != nil {
		t.Fatalf("read CancelRequest: %v", err)
	}
	if code, ok := StartupCode(gotCancel); !ok || code != CancelRequestCode {
		t.Fatalf("expected CancelRequestCode, got %d", code)
	}

	startup := BuildStartupPacket(map[string]string{
		"user":             "app_svc",
		"database":         "orders_prod",
		"application_name": "billing-worker",
	})
	buf.Reset()
	if _, err := startup.WriteTo(&buf); err != nil {
		t.Fatalf("write startup: %v", err)
	}
	gotStartup, err := ReadStartupPacket(&buf)
	if err != nil {
		t.Fatalf("read startup: %v", err)
	}
	params := ParseStartupParams(gotStartup)
	if params["user"] != "app_svc" || params["database"] != "orders_prod" || params["application_name"] != "billing-worker" {
		t.Fatalf("unexpected startup params: %+v", params)
	}
}

func TestExtractQuerySimple(t *testing.T) {
	sql := "SELECT * FROM users WHERE id = 1"
	pkt := BuildQueryPacket(sql)

	q, err := pkt.ExtractQuery()
	if err != nil {
		t.Fatalf("ExtractQuery failed: %v", err)
	}
	if q != sql {
		t.Fatalf("expected %q, got %q", sql, q)
	}
}

func TestExtractExtendedQueryMessages(t *testing.T) {
	stmt := "stmt_user_lookup"
	sql := "UPDATE accounts SET balance = balance - 100 WHERE id = $1"
	parsePkt := BuildParsePacket(stmt, sql, 23, 25)

	gotStmt, gotSQL, gotOIDs, err := parsePkt.ExtractParse()
	if err != nil {
		t.Fatalf("ExtractParse failed: %v", err)
	}
	if gotStmt != stmt || gotSQL != sql {
		t.Fatalf("unexpected parse decode: stmt=%q sql=%q", gotStmt, gotSQL)
	}
	if len(gotOIDs) != 2 || gotOIDs[0] != 23 || gotOIDs[1] != 25 {
		t.Fatalf("unexpected OIDs: %v", gotOIDs)
	}
	q, err := parsePkt.ExtractQuery()
	if err != nil || q != sql {
		t.Fatalf("ExtractQuery parse failed: %v, %q", err, q)
	}

	bindPkt := BuildBindPacket("portal_1", stmt)
	portal, boundStmt, err := bindPkt.ExtractBind()
	if err != nil {
		t.Fatalf("ExtractBind failed: %v", err)
	}
	if portal != "portal_1" || boundStmt != stmt {
		t.Fatalf("unexpected bind decode: portal=%q stmt=%q", portal, boundStmt)
	}

	execPkt := BuildExecutePacket("portal_1", 100)
	execPortal, maxRows, err := execPkt.ExtractExecute()
	if err != nil {
		t.Fatalf("ExtractExecute failed: %v", err)
	}
	if execPortal != "portal_1" || maxRows != 100 {
		t.Fatalf("unexpected execute decode: portal=%q maxRows=%d", execPortal, maxRows)
	}

	closePkt := BuildClosePacket('S', stmt)
	targetType, targetName, err := closePkt.ExtractClose()
	if err != nil {
		t.Fatalf("ExtractClose failed: %v", err)
	}
	if targetType != 'S' || targetName != stmt {
		t.Fatalf("unexpected close decode: type=%c name=%q", targetType, targetName)
	}
}

func TestBuildReadyForQueryAndNotice(t *testing.T) {
	pkt := BuildReadyForQuery(TxInBlock)
	status, err := pkt.ExtractReadyForQuery()
	if err != nil || status != TxInBlock {
		t.Fatalf("unexpected ReadyForQuery: status=%c err=%v", status, err)
	}

	notice := BuildNoticeResponse("WARNING", "54000", "non-concurrent drop", "use CONCURRENTLY")
	fields, err := ParseErrorResponse(notice)
	if err != nil {
		t.Fatalf("ParseErrorResponse on notice failed: %v", err)
	}
	if fields.Severity != "WARNING" || fields.Code != "54000" {
		t.Fatalf("unexpected notice fields: %+v", fields)
	}
}

func TestReadPacketInvalidLength(t *testing.T) {
	var raw [5]byte
	raw[0] = MsgQuery
	binary.BigEndian.PutUint32(raw[1:5], 2) // < 4 is invalid
	_, err := ReadPacket(bytes.NewReader(raw[:]))
	if !errors.Is(err, ErrInvalidPacketLen) {
		t.Fatalf("expected ErrInvalidPacketLen, got %v", err)
	}

	var startupRaw [4]byte
	binary.BigEndian.PutUint32(startupRaw[:], 99999) // > 10000 is invalid
	_, err = ReadStartupPacket(bytes.NewReader(startupRaw[:]))
	if !errors.Is(err, ErrInvalidPacketLen) {
		t.Fatalf("expected ErrInvalidPacketLen on startup, got %v", err)
	}
}
