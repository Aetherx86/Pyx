package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// PostgreSQL 3.0 Protocol Constants
const (
	ProtocolVersion3 = 196608 // 3.0 (0x00030000)
	SSLRequestCode   = 80877103

	MsgQuery        = 'Q'
	MsgParse        = 'P'
	MsgBind         = 'B'
	MsgExecute      = 'E'
	MsgSync         = 'S'
	MsgTerminate    = 'X'
	MsgPassword     = 'p'
	MsgDescribe     = 'D'
	MsgClose        = 'C'
	MsgFlush        = 'H'

	BackendErrorResponse   = 'E'
	BackendNoticeResponse  = 'N'
	BackendReadyForQuery   = 'Z'
	BackendCommandComplete = 'C'
	BackendRowDescription  = 'T'
	BackendDataRow         = 'D'
)

var (
	ErrIncompletePacket = errors.New("incomplete postgres packet")
	ErrInvalidPacketLen = errors.New("invalid packet length")
)

// Packet represents a framed PostgreSQL wire protocol message.
type Packet struct {
	Type    byte   // 0 for startup packet
	Length  int32  // Length includes itself (4 bytes), but not Type
	Payload []byte // Message body excluding Type and Length
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
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
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

// WritePacket writes a typed packet to an io.Writer.
func (p *Packet) WriteTo(w io.Writer) error {
	if p.Type == 0 {
		// Startup message without type prefix
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(p.Length))
		if _, err := w.Write(lenBuf[:]); err != nil {
			return err
		}
		_, err := w.Write(p.Payload)
		return err
	}

	var header [5]byte
	header[0] = p.Type
	binary.BigEndian.PutUint32(header[1:5], uint32(p.Length))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(p.Payload) > 0 {
		_, err := w.Write(p.Payload)
		return err
	}
	return nil
}

// ExtractQuery extracts the raw SQL query string from 'Q' (Query) or 'P' (Parse) packets.
func (p *Packet) ExtractQuery() (string, error) {
	switch p.Type {
	case MsgQuery:
		// Simple query: null-terminated string
		idx := bytes.IndexByte(p.Payload, 0)
		if idx < 0 {
			return string(p.Payload), nil
		}
		return string(p.Payload[:idx]), nil

	case MsgParse:
		// Parse message:
		// String destination statement name (null-terminated)
		// String query string (null-terminated)
		firstNull := bytes.IndexByte(p.Payload, 0)
		if firstNull < 0 || firstNull+1 >= len(p.Payload) {
			return "", errors.New("malformed parse packet")
		}
		remainder := p.Payload[firstNull+1:]
		secondNull := bytes.IndexByte(remainder, 0)
		if secondNull < 0 {
			return string(remainder), nil
		}
		return string(remainder[:secondNull]), nil

	default:
		return "", fmt.Errorf("packet type 0x%02x is not a query carrier", p.Type)
	}
}

// BuildErrorResponse constructs an official PostgreSQL wire-level ErrorResponse packet ('E').
// severity: ERROR, FATAL, PANIC
// code: 5-character SQLSTATE (e.g. 55P03 for lock_not_available, 54000 for program_limit_exceeded)
// message: primary human-readable diagnostic error message
// detail: supplementary explanatory details
func BuildErrorResponse(severity, code, message, detail string) *Packet {
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
		Type:    BackendErrorResponse,
		Length:  int32(len(payload) + 4),
		Payload: payload,
	}
}

// BuildReadyForQuery constructs a ReadyForQuery packet ('Z') with status 'I' (Idle).
func BuildReadyForQuery(txStatus byte) *Packet {
	return &Packet{
		Type:    BackendReadyForQuery,
		Length:  5,
		Payload: []byte{txStatus},
	}
}
