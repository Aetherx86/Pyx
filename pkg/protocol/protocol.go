package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

// PostgreSQL 3.0 Protocol Constants
const (
	ProtocolVersion3  = 196608   // 3.0 (0x00030000)
	CancelRequestCode = 80877102 // (1234 << 16) | 5678
	SSLRequestCode    = 80877103 // (1234 << 16) | 5679
	GSSENCRequestCode = 80877104 // (1234 << 16) | 5680

	// Frontend message types
	MsgQuery     = 'Q'
	MsgParse     = 'P'
	MsgBind      = 'B'
	MsgExecute   = 'E'
	MsgSync      = 'S'
	MsgTerminate = 'X'
	MsgPassword  = 'p'
	MsgDescribe  = 'D'
	MsgClose     = 'C'
	MsgFlush     = 'H'

	// Backend message types
	BackendAuthentication       = 'R'
	BackendParameterStatus      = 'S'
	BackendErrorResponse        = 'E'
	BackendNoticeResponse       = 'N'
	BackendReadyForQuery        = 'Z'
	BackendCommandComplete      = 'C'
	BackendRowDescription       = 'T'
	BackendDataRow              = 'D'
	BackendParseComplete        = '1'
	BackendBindComplete         = '2'
	BackendCloseComplete        = '3'
	BackendNoData               = 'n'
	BackendPortalSuspended      = 's'
	BackendEmptyQueryResponse   = 'I'
	BackendParameterDescription = 't'

	// ReadyForQuery transaction status indicators
	TxIdle    byte = 'I'
	TxInBlock byte = 'T'
	TxFailed  byte = 'E'
)

var (
	ErrIncompletePacket = errors.New("incomplete postgres packet")
	ErrInvalidPacketLen = errors.New("invalid packet length")
)

// Packet represents a framed PostgreSQL wire protocol message.
type Packet struct {
	Type    byte   // 0 for startup/negotiation packets
	Length  int32  // Length includes itself (4 bytes), but not Type
	Payload []byte // Message body excluding Type and Length
}

// ErrorFields holds decoded fields from a PostgreSQL ErrorResponse or NoticeResponse packet.
type ErrorFields struct {
	Severity  string
	Localized string
	Code      string
	Message   string
	Detail    string
	Hint      string
	Routine   string
}

// ReadStartupPacket reads the initial client connection packet (no type byte).
func ReadStartupPacket(r io.Reader) (*Packet, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	pktLen := int32(binary.BigEndian.Uint32(lenBuf[:]))
	if pktLen < 4 || pktLen > 10000 {
		return nil, ErrInvalidPacketLen
	}
	payload := make([]byte, pktLen-4)
	if pktLen > 4 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}
	return &Packet{
		Type:    0,
		Length:  pktLen,
		Payload: payload,
	}, nil
}

// ReadPacket reads a standard typed PostgreSQL packet from an io.Reader.
func ReadPacket(r io.Reader) (*Packet, error) {
	var header [5]byte // 1 byte Type + 4 bytes Length
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	pktType := header[0]
	pktLen := int32(binary.BigEndian.Uint32(header[1:5]))
	if pktLen < 4 || pktLen > 67108864 { // 64 MB maximum message safety boundary
		return nil, ErrInvalidPacketLen
	}

	payloadLen := pktLen - 4
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}

	return &Packet{
		Type:    pktType,
		Length:  pktLen,
		Payload: payload,
	}, nil
}

// WriteTo implements io.WriterTo, writing the framed packet to w.
func (p *Packet) WriteTo(w io.Writer) (int64, error) {
	pktLen := p.Length
	if pktLen == 0 {
		pktLen = int32(len(p.Payload) + 4)
	}

	if p.Type == 0 {
		total := 4 + len(p.Payload)
		if total <= 4096 {
			var stackBuf [4096]byte
			binary.BigEndian.PutUint32(stackBuf[:4], uint32(pktLen))
			copy(stackBuf[4:], p.Payload)
			n, err := w.Write(stackBuf[:total])
			return int64(n), err
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(pktLen))
		n1, err := w.Write(lenBuf[:])
		if err != nil {
			return int64(n1), err
		}
		n2, err := w.Write(p.Payload)
		return int64(n1 + n2), err
	}

	total := 5 + len(p.Payload)
	if total <= 4096 {
		var stackBuf [4096]byte
		stackBuf[0] = p.Type
		binary.BigEndian.PutUint32(stackBuf[1:5], uint32(pktLen))
		copy(stackBuf[5:], p.Payload)
		n, err := w.Write(stackBuf[:total])
		return int64(n), err
	}

	var header [5]byte
	header[0] = p.Type
	binary.BigEndian.PutUint32(header[1:5], uint32(pktLen))
	n1, err := w.Write(header[:])
	if err != nil {
		return int64(n1), err
	}
	if len(p.Payload) > 0 {
		n2, err := w.Write(p.Payload)
		return int64(n1 + n2), err
	}
	return int64(n1), nil
}

// StartupCode returns the 32-bit protocol version or special request code from a startup packet.
func StartupCode(p *Packet) (int32, bool) {
	if p == nil || p.Type != 0 || len(p.Payload) < 4 {
		return 0, false
	}
	return int32(binary.BigEndian.Uint32(p.Payload[:4])), true
}

// ParseStartupParams decodes key/value connection parameters from a v3.0 startup message.
func ParseStartupParams(p *Packet) map[string]string {
	params := make(map[string]string)
	code, ok := StartupCode(p)
	if !ok || code != ProtocolVersion3 || len(p.Payload) <= 4 {
		return params
	}
	rest := p.Payload[4:]
	for len(rest) > 0 {
		keyEnd := bytes.IndexByte(rest, 0)
		if keyEnd <= 0 {
			break
		}
		key := string(rest[:keyEnd])
		rest = rest[keyEnd+1:]
		valEnd := bytes.IndexByte(rest, 0)
		if valEnd < 0 {
			break
		}
		params[key] = string(rest[:valEnd])
		rest = rest[valEnd+1:]
	}
	return params
}

// ExtractQuery extracts the raw SQL query string from 'Q' (Query) or 'P' (Parse) packets.
func (p *Packet) ExtractQuery() (string, error) {
	switch p.Type {
	case MsgQuery:
		idx := bytes.IndexByte(p.Payload, 0)
		if idx < 0 {
			return string(p.Payload), nil
		}
		return string(p.Payload[:idx]), nil

	case MsgParse:
		_, q, _, err := p.ExtractParse()
		return q, err

	default:
		return "", fmt.Errorf("packet type 0x%02x is not a query carrier", p.Type)
	}
}

// ExtractParse decodes statement name, SQL query text, and parameter type OIDs from a Parse ('P') packet.
func (p *Packet) ExtractParse() (stmtName, query string, paramOIDs []uint32, err error) {
	if p.Type != MsgParse {
		return "", "", nil, fmt.Errorf("expected Parse packet, got 0x%02x", p.Type)
	}
	firstNull := bytes.IndexByte(p.Payload, 0)
	if firstNull < 0 || firstNull+1 >= len(p.Payload) {
		return "", "", nil, errors.New("malformed parse packet")
	}
	stmtName = string(p.Payload[:firstNull])
	remainder := p.Payload[firstNull+1:]

	secondNull := bytes.IndexByte(remainder, 0)
	if secondNull < 0 {
		return stmtName, string(remainder), nil, nil
	}
	query = string(remainder[:secondNull])
	afterQuery := remainder[secondNull+1:]
	if len(afterQuery) >= 2 {
		count := int(binary.BigEndian.Uint16(afterQuery[:2]))
		afterQuery = afterQuery[2:]
		if count > 0 && len(afterQuery) >= count*4 {
			paramOIDs = make([]uint32, count)
			for i := 0; i < count; i++ {
				paramOIDs[i] = binary.BigEndian.Uint32(afterQuery[i*4 : (i+1)*4])
			}
		}
	}
	return stmtName, query, paramOIDs, nil
}

// ExtractBind decodes the destination portal name and source prepared statement name from a Bind ('B') packet.
func (p *Packet) ExtractBind() (portalName, stmtName string, err error) {
	if p.Type != MsgBind {
		return "", "", fmt.Errorf("expected Bind packet, got 0x%02x", p.Type)
	}
	firstNull := bytes.IndexByte(p.Payload, 0)
	if firstNull < 0 || firstNull+1 >= len(p.Payload) {
		return "", "", errors.New("malformed bind packet")
	}
	portalName = string(p.Payload[:firstNull])
	remainder := p.Payload[firstNull+1:]
	secondNull := bytes.IndexByte(remainder, 0)
	if secondNull < 0 {
		return "", "", errors.New("malformed bind packet: unterminated statement name")
	}
	stmtName = string(remainder[:secondNull])
	return portalName, stmtName, nil
}

// ExtractExecute decodes the portal name and max row count from an Execute ('E') packet.
func (p *Packet) ExtractExecute() (portalName string, maxRows int32, err error) {
	if p.Type != MsgExecute {
		return "", 0, fmt.Errorf("expected Execute packet, got 0x%02x", p.Type)
	}
	nullIdx := bytes.IndexByte(p.Payload, 0)
	if nullIdx < 0 || nullIdx+5 > len(p.Payload) {
		return "", 0, errors.New("malformed execute packet")
	}
	portalName = string(p.Payload[:nullIdx])
	maxRows = int32(binary.BigEndian.Uint32(p.Payload[nullIdx+1 : nullIdx+5]))
	return portalName, maxRows, nil
}

// ExtractClose decodes the target type ('S' for statement, 'P' for portal) and name from a Close ('C') packet.
func (p *Packet) ExtractClose() (targetType byte, name string, err error) {
	if p.Type != MsgClose {
		return 0, "", fmt.Errorf("expected Close packet, got 0x%02x", p.Type)
	}
	if len(p.Payload) < 2 {
		return 0, "", errors.New("malformed close packet")
	}
	targetType = p.Payload[0]
	rest := p.Payload[1:]
	nullIdx := bytes.IndexByte(rest, 0)
	if nullIdx < 0 {
		return targetType, string(rest), nil
	}
	return targetType, string(rest[:nullIdx]), nil
}

// ExtractReadyForQuery returns the transaction status byte ('I', 'T', or 'E') from a ReadyForQuery packet.
func (p *Packet) ExtractReadyForQuery() (byte, error) {
	if p.Type != BackendReadyForQuery || len(p.Payload) != 1 {
		return 0, errors.New("malformed ReadyForQuery packet")
	}
	return p.Payload[0], nil
}

// ParseErrorResponse decodes structured fields from an ErrorResponse ('E') or NoticeResponse ('N') packet.
func ParseErrorResponse(p *Packet) (ErrorFields, error) {
	if p == nil || (p.Type != BackendErrorResponse && p.Type != BackendNoticeResponse) {
		return ErrorFields{}, errors.New("packet is not an ErrorResponse or NoticeResponse")
	}
	var fields ErrorFields
	rest := p.Payload
	for len(rest) > 0 {
		fieldType := rest[0]
		if fieldType == 0 {
			break
		}
		rest = rest[1:]
		nullIdx := bytes.IndexByte(rest, 0)
		if nullIdx < 0 {
			break
		}
		val := string(rest[:nullIdx])
		rest = rest[nullIdx+1:]
		switch fieldType {
		case 'S':
			fields.Localized = val
		case 'V':
			fields.Severity = val
		case 'C':
			fields.Code = val
		case 'M':
			fields.Message = val
		case 'D':
			fields.Detail = val
		case 'H':
			fields.Hint = val
		case 'R':
			fields.Routine = val
		}
	}
	if fields.Severity == "" {
		fields.Severity = fields.Localized
	}
	return fields, nil
}

// BuildStartupPacket constructs a PostgreSQL v3.0 StartupMessage packet with sorted key/value parameters.
func BuildStartupPacket(params map[string]string) *Packet {
	var buf bytes.Buffer
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], ProtocolVersion3)
	buf.Write(ver[:])

	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteByte(0)
		buf.WriteString(params[k])
		buf.WriteByte(0)
	}
	buf.WriteByte(0)

	payload := buf.Bytes()
	return &Packet{
		Type:    0,
		Length:  int32(len(payload) + 4),
		Payload: payload,
	}
}

// BuildSSLRequestPacket constructs an 8-byte SSLRequest startup negotiation packet.
func BuildSSLRequestPacket() *Packet {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, SSLRequestCode)
	return &Packet{
		Type:    0,
		Length:  8,
		Payload: payload,
	}
}

// BuildGSSENCRequestPacket constructs an 8-byte GSSENCRequest startup negotiation packet.
func BuildGSSENCRequestPacket() *Packet {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, GSSENCRequestCode)
	return &Packet{
		Type:    0,
		Length:  8,
		Payload: payload,
	}
}

// BuildCancelRequestPacket constructs a 16-byte PostgreSQL CancelRequest packet.
func BuildCancelRequestPacket(pid, secret int32) *Packet {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[0:4], CancelRequestCode)
	binary.BigEndian.PutUint32(payload[4:8], uint32(pid))
	binary.BigEndian.PutUint32(payload[8:12], uint32(secret))
	return &Packet{
		Type:    0,
		Length:  16,
		Payload: payload,
	}
}

// BuildQueryPacket constructs a Simple Query ('Q') frontend packet.
func BuildQueryPacket(sql string) *Packet {
	payload := make([]byte, len(sql)+1)
	copy(payload, sql)
	return &Packet{
		Type:    MsgQuery,
		Length:  int32(len(payload) + 4),
		Payload: payload,
	}
}

// BuildParsePacket constructs an Extended Query Parse ('P') frontend packet.
func BuildParsePacket(stmtName, sql string, paramOIDs ...uint32) *Packet {
	var buf bytes.Buffer
	buf.WriteString(stmtName)
	buf.WriteByte(0)
	buf.WriteString(sql)
	buf.WriteByte(0)
	var countBuf [2]byte
	binary.BigEndian.PutUint16(countBuf[:], uint16(len(paramOIDs)))
	buf.Write(countBuf[:])
	for _, oid := range paramOIDs {
		var oidBuf [4]byte
		binary.BigEndian.PutUint32(oidBuf[:], oid)
		buf.Write(oidBuf[:])
	}
	payload := buf.Bytes()
	return &Packet{
		Type:    MsgParse,
		Length:  int32(len(payload) + 4),
		Payload: payload,
	}
}

// BuildBindPacket constructs a minimal Bind ('B') frontend packet with zero parameters.
func BuildBindPacket(portalName, stmtName string) *Packet {
	var buf bytes.Buffer
	buf.WriteString(portalName)
	buf.WriteByte(0)
	buf.WriteString(stmtName)
	buf.WriteByte(0)
	// 0 parameter format codes, 0 parameter values, 0 result format codes
	buf.Write([]byte{0, 0, 0, 0, 0, 0})
	payload := buf.Bytes()
	return &Packet{
		Type:    MsgBind,
		Length:  int32(len(payload) + 4),
		Payload: payload,
	}
}

// BuildExecutePacket constructs an Execute ('E') frontend packet.
func BuildExecutePacket(portalName string, maxRows int32) *Packet {
	payload := make([]byte, len(portalName)+5)
	copy(payload, portalName)
	binary.BigEndian.PutUint32(payload[len(portalName)+1:], uint32(maxRows))
	return &Packet{
		Type:    MsgExecute,
		Length:  int32(len(payload) + 4),
		Payload: payload,
	}
}

// BuildDescribePacket constructs a Describe ('D') frontend packet ('S' or 'P').
func BuildDescribePacket(targetType byte, name string) *Packet {
	payload := make([]byte, 1+len(name)+1)
	payload[0] = targetType
	copy(payload[1:], name)
	return &Packet{
		Type:    MsgDescribe,
		Length:  int32(len(payload) + 4),
		Payload: payload,
	}
}

// BuildClosePacket constructs a Close ('C') frontend packet ('S' or 'P').
func BuildClosePacket(targetType byte, name string) *Packet {
	payload := make([]byte, 1+len(name)+1)
	payload[0] = targetType
	copy(payload[1:], name)
	return &Packet{
		Type:    MsgClose,
		Length:  int32(len(payload) + 4),
		Payload: payload,
	}
}

// BuildSyncPacket constructs a Sync ('S') frontend packet.
func BuildSyncPacket() *Packet {
	return &Packet{
		Type:   MsgSync,
		Length: 4,
	}
}

// BuildFlushPacket constructs a Flush ('H') frontend packet.
func BuildFlushPacket() *Packet {
	return &Packet{
		Type:   MsgFlush,
		Length: 4,
	}
}

// BuildTerminatePacket constructs a Terminate ('X') frontend packet.
func BuildTerminatePacket() *Packet {
	return &Packet{
		Type:   MsgTerminate,
		Length: 4,
	}
}

func buildDiagResponse(pktType byte, severity, code, message, detail string) *Packet {
	var buf bytes.Buffer

	// Field 'S': Severity
	buf.WriteByte('S')
	buf.WriteString(severity)
	buf.WriteByte(0)

	// Field 'V': Severity (non-localized)
	buf.WriteByte('V')
	buf.WriteString(severity)
	buf.WriteByte(0)

	// Field 'C': SQLSTATE Code
	buf.WriteByte('C')
	buf.WriteString(code)
	buf.WriteByte(0)

	// Field 'M': Primary Message
	buf.WriteByte('M')
	buf.WriteString(message)
	buf.WriteByte(0)

	// Field 'D': Detail (optional)
	if detail != "" {
		buf.WriteByte('D')
		buf.WriteString(detail)
		buf.WriteByte(0)
	}

	// Field 'R': Routine
	buf.WriteByte('R')
	buf.WriteString("PyxGatekeeperEnforce")
	buf.WriteByte(0)

	// Terminating null byte
	buf.WriteByte(0)

	payload := buf.Bytes()
	return &Packet{
		Type:    pktType,
		Length:  int32(len(payload) + 4),
		Payload: payload,
	}
}

// BuildErrorResponse constructs an official PostgreSQL wire-level ErrorResponse packet ('E').
// severity: ERROR, FATAL, PANIC
// code: 5-character SQLSTATE (e.g. 55P03 for lock_not_available, 54000 for program_limit_exceeded)
// message: primary human-readable diagnostic error message
// detail: supplementary explanatory details
func BuildErrorResponse(severity, code, message, detail string) *Packet {
	return buildDiagResponse(BackendErrorResponse, severity, code, message, detail)
}

// BuildNoticeResponse constructs a PostgreSQL NoticeResponse packet ('N').
func BuildNoticeResponse(severity, code, message, detail string) *Packet {
	return buildDiagResponse(BackendNoticeResponse, severity, code, message, detail)
}

// BuildReadyForQuery constructs a ReadyForQuery packet ('Z') with status 'I', 'T', or 'E'.
func BuildReadyForQuery(txStatus byte) *Packet {
	return &Packet{
		Type:    BackendReadyForQuery,
		Length:  5,
		Payload: []byte{txStatus},
	}
}

// BuildCommandComplete constructs a CommandComplete ('C') backend packet.
func BuildCommandComplete(tag string) *Packet {
	payload := make([]byte, len(tag)+1)
	copy(payload, tag)
	return &Packet{
		Type:    BackendCommandComplete,
		Length:  int32(len(payload) + 4),
		Payload: payload,
	}
}

// BuildParseComplete constructs a ParseComplete ('1') backend packet.
func BuildParseComplete() *Packet {
	return &Packet{Type: BackendParseComplete, Length: 4}
}

// BuildBindComplete constructs a BindComplete ('2') backend packet.
func BuildBindComplete() *Packet {
	return &Packet{Type: BackendBindComplete, Length: 4}
}

// BuildCloseComplete constructs a CloseComplete ('3') backend packet.
func BuildCloseComplete() *Packet {
	return &Packet{Type: BackendCloseComplete, Length: 4}
}
