package packets

import (
	"github.com/goodieshq/goflo/internal/protocol"
	"github.com/oklog/ulid/v2"
)

// Answer packet sent by the client in response to a challenge
type PktAnswer struct {
	protocol.Header           // Common packet header
	SessionID       ulid.ULID // Unique session identifier
	AuthHash        [32]byte  // SHA-256 HMAC of the challenge nonces
}

const PktAnswerSize = protocol.HeaderSize + 16 + 32

func UnmarshalAnswer(data []byte) (*PktAnswer, error) {
	if len(data) != PktAnswerSize {
		return nil, protocol.ErrInvalidPacketSize
	}

	header, err := protocol.UnmarshalHeader(data[0:protocol.HeaderSize])
	if err != nil {
		return nil, err
	}

	if header.Type != TypeAnswer {
		return nil, protocol.ErrIncorrectType
	}

	var pkt PktAnswer
	pkt.Header = *header
	copy(pkt.SessionID[:], data[6:22])
	copy(pkt.AuthHash[:], data[22:54])

	return &pkt, nil
}

func (p *PktAnswer) Marshal() ([]byte, error) {
	buf := make([]byte, PktAnswerSize)

	if p.Header.Magic != [4]byte{'F', 'L', 'O', 0x00} {
		return nil, protocol.ErrInvalidMagic
	}

	copy(buf[0:4], p.Header.Magic[:])
	buf[4] = byte(p.Header.Version)
	buf[5] = byte(p.Header.Type)
	copy(buf[6:22], p.SessionID[:])
	copy(buf[22:54], p.AuthHash[:])
	return buf, nil
}

func NewAnswer(sessionID ulid.ULID, authHash [32]byte) (*PktAnswer, error) {
	var pkt PktAnswer

	pkt.Header = createHeader(TypeAnswer)
	copy(pkt.SessionID[:], sessionID[:])
	copy(pkt.AuthHash[:], authHash[:])

	return &pkt, nil
}
