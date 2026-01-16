package packets

import (
	"github.com/goodieshq/goflo/internal/protocol"
	"github.com/oklog/ulid/v2"
)

// Challenge packet sent by the server (if authentication is enabled)
type PktChallenge struct {
	protocol.Header           // Common packet header
	SessionID       ulid.ULID // Unique session identifier
	AuthMethod      FloAuth   // Authentication method (e.g., HMAC)
	NonceServer     [16]byte  // Server nonce for authentication
}

const PktChallengeSize = protocol.HeaderSize + 16 + 1 + 16

func UnmarshalChallenge(data []byte) (*PktChallenge, error) {
	if len(data) != PktChallengeSize {
		return nil, protocol.ErrInvalidPacketSize
	}

	header, err := protocol.UnmarshalHeader(data[0:protocol.HeaderSize])
	if err != nil {
		return nil, err
	}

	if header.Type != TypeChallenge {
		return nil, protocol.ErrIncorrectType
	}

	var pkt PktChallenge

	pkt.Header = *header
	copy(pkt.SessionID[:], data[6:22])
	pkt.AuthMethod = FloAuth(data[22])
	copy(pkt.NonceServer[:], data[23:39])

	return &pkt, nil
}

func (p *PktChallenge) Marshal() ([]byte, error) {
	buf := make([]byte, PktChallengeSize)

	if p.Header.Magic != [4]byte{'F', 'L', 'O', 0x00} {
		return nil, protocol.ErrInvalidMagic
	}

	copy(buf[0:4], p.Header.Magic[:])
	buf[4] = byte(p.Header.Version)
	buf[5] = byte(p.Header.Type)
	copy(buf[6:22], p.SessionID[:])
	buf[22] = byte(p.AuthMethod)
	copy(buf[23:39], p.NonceServer[:])
	return buf, nil
}

func NewChallenge(sessionID ulid.ULID, authMethod FloAuth, nonce [16]byte) (*PktChallenge, error) {
	var pkt PktChallenge

	pkt.Header = createHeader(TypeChallenge)

	copy(pkt.SessionID[:], sessionID[:])
	pkt.AuthMethod = authMethod
	copy(pkt.NonceServer[:], nonce[:])

	return &pkt, nil
}
