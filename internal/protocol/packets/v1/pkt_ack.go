package packets

import (
	"github.com/goodieshq/goflo/internal/protocol"
	"github.com/oklog/ulid/v2"
)

type PktAck struct {
	protocol.Header            // Common packet header
	SessionID       ulid.ULID  // Unique session identifier
	Auth            FloAuth    // Authentication type used
	Code            FloAckCode // Acknowledgment code (OK, Error, etc.)
}

const PktAckSize = protocol.HeaderSize + 16 + 1 + 1

func UnmarshalAck(data []byte) (*PktAck, error) {
	if len(data) != PktAckSize {
		return nil, protocol.ErrInvalidPacketSize
	}

	header, err := protocol.UnmarshalHeader(data[0:protocol.HeaderSize])
	if err != nil {
		return nil, err
	}

	if header.Type != TypeAck {
		return nil, protocol.ErrIncorrectType
	}

	var pkt PktAck
	pkt.Header = *header
	copy(pkt.SessionID[:], data[6:22])
	pkt.Auth = FloAuth(data[22])
	pkt.Code = FloAckCode(data[23])

	return &pkt, nil
}

func (p *PktAck) Marshal() ([]byte, error) {
	buf := make([]byte, PktAckSize)

	if p.Header.Magic != [4]byte{'F', 'L', 'O', 0x00} {
		return nil, protocol.ErrInvalidMagic
	}

	copy(buf[0:4], p.Header.Magic[:])
	buf[4] = byte(p.Header.Version)
	buf[5] = byte(p.Header.Type)
	copy(buf[6:22], p.SessionID[:])
	buf[22] = byte(p.Auth)
	buf[23] = byte(p.Code)
	return buf, nil
}

func NewAck(sessionID ulid.ULID, auth FloAuth, code FloAckCode) (*PktAck, error) {
	var pkt PktAck

	pkt.Header = createHeader(TypeAck)

	copy(pkt.SessionID[:], sessionID[:])
	pkt.Auth = auth
	pkt.Code = code
	return &pkt, nil
}
