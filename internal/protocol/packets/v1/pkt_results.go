package packets

import (
	"github.com/goodieshq/goflo/internal/protocol"
	"github.com/oklog/ulid/v2"
)

type PktResult struct {
	protocol.Header           // Common packet header
	SessionID       ulid.ULID // Unique session identifier
	BytesSent       uint64    // Total bytes sent during the test
	BytesReceived   uint64    // Total bytes received during the test
}

const PktResultSize = protocol.HeaderSize + 16 + 8 + 8

func NewResult(sessionID ulid.ULID, bytesSent, bytesReceived uint64) (*PktResult, error) {
	var pkt PktResult

	pkt.Header = createHeader(TypeResult)
	copy(pkt.SessionID[:], sessionID[:])
	pkt.BytesSent = bytesSent
	pkt.BytesReceived = bytesReceived

	return &pkt, nil
}

func (p *PktResult) Marshal() ([]byte, error) {
	buf := make([]byte, PktResultSize)

	if p.Header.Magic != [4]byte{'F', 'L', 'O', 0x00} {
		return nil, protocol.ErrInvalidMagic
	}

	copy(buf[0:4], p.Header.Magic[:])
	buf[4] = byte(p.Header.Version)
	buf[5] = byte(p.Header.Type)
	copy(buf[6:22], p.SessionID[:])
	le.PutUint64(buf[22:30], p.BytesSent)
	le.PutUint64(buf[30:38], p.BytesReceived)
	return buf, nil
}

func UnmarshalResult(data []byte) (*PktResult, error) {
	if len(data) != PktResultSize {
		return nil, protocol.ErrInvalidPacketSize
	}

	header, err := protocol.UnmarshalHeader(data[0:protocol.HeaderSize])
	if err != nil {
		return nil, err
	}

	if header.Type != TypeResult {
		return nil, protocol.ErrIncorrectType
	}

	var pkt PktResult
	pkt.Header = *header
	copy(pkt.SessionID[:], data[6:22])
	pkt.BytesSent = le.Uint64(data[22:30])
	pkt.BytesReceived = le.Uint64(data[30:38])

	return &pkt, nil
}
