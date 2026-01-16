package packets

import (
	"time"

	"github.com/goodieshq/goflo/internal/protocol"
	"github.com/goodieshq/goflo/internal/utils"
	"github.com/oklog/ulid/v2"
)

// Hello packet sent by the client to initiate a connection
type PktHello struct {
	protocol.Header                 // Common packet header
	SessionID       ulid.ULID       // Unique session identifier
	Transport       FloTransport    // Transport type (TCP/UDP/SCTP/QUIC/etc)
	Security        FloSecurity     // Security type (None/TLS)
	Direction       protocol.FloDir // Direction of data flow (BiDi/Upload/Download)
	Flags           FloFlags        // Optional flags (reserved for future use)
	ChunkSize       uint32          // Size of each data chunk
	DurationMS      uint64          // Intended duration of the flo test in milliseconds
	WarmupMS        uint64          // Warmup period in milliseconds
	NonceClient     [16]byte        // Client nonce for authentication
}

const PktHelloSize = protocol.HeaderSize + 16 + 1 + 1 + 1 + 2 + 4 + 8 + 8 + 16

func UnmarshalHello(data []byte) (*PktHello, error) {
	if len(data) != PktHelloSize {
		return nil, protocol.ErrInvalidPacketSize
	}

	header, err := protocol.UnmarshalHeader(data[0:protocol.HeaderSize])
	if err != nil {
		return nil, err
	}

	if header.Type != TypeHello {
		return nil, protocol.ErrIncorrectType
	}

	var pkt PktHello

	pkt.Header = *header
	copy(pkt.SessionID[:], data[6:22])

	pkt.Transport = FloTransport(data[22])
	switch pkt.Transport {
	case TransportTCP, TransportUDP, TransportSCTP:
		// Supported transports
	default:
		return nil, protocol.ErrUnsupportedTransport
	}

	pkt.Security = FloSecurity(data[23])
	switch pkt.Security {
	case SecurityNone, SecurityTLS:
		// Supported security types
	default:
		return nil, protocol.ErrUnsupportedSecurity
	}

	pkt.Direction = protocol.FloDir(data[24])
	switch pkt.Direction {
	case protocol.DirectionBidi, protocol.DirectionUpload, protocol.DirectionDownload:
		// Supported directions
	default:
		return nil, protocol.ErrUnsupportedDirection
	}

	pkt.Flags = FloFlags(le.Uint16(data[25:27]))
	if pkt.Flags != 0 {
		return nil, protocol.ErrInvalidFlags
	}

	pkt.ChunkSize = le.Uint32(data[27:31])
	// Validate chunk size (e.g., between 1KB and 10MB)
	if pkt.ChunkSize < 10 || pkt.ChunkSize > 10*1000*1000 {
		return nil, protocol.ErrInvalidChunkSize
	}

	pkt.DurationMS = le.Uint64(data[31:39])
	if pkt.DurationMS < 1000 {
		return nil, protocol.ErrInvalidDuration
	}

	pkt.WarmupMS = le.Uint64(data[39:47])

	// Copy the client nonce
	copy(pkt.NonceClient[:], data[47:63])
	var chk byte = 0
	for _, b := range pkt.NonceClient {
		chk |= b
	}
	if chk == 0 {
		// Client nonce cannot be all zeros
		return nil, protocol.ErrInvalidNonce
	}

	return &pkt, nil
}

func (p *PktHello) Marshal() ([]byte, error) {
	buf := make([]byte, PktHelloSize)

	if p.Header.Magic != [4]byte{'F', 'L', 'O', 0x00} {
		return nil, protocol.ErrInvalidMagic
	}

	copy(buf[0:4], p.Header.Magic[:])
	buf[4] = byte(p.Header.Version)
	buf[5] = byte(p.Header.Type)
	copy(buf[6:22], p.SessionID[:])
	buf[22] = byte(p.Transport)
	buf[23] = byte(p.Security)
	buf[24] = byte(p.Direction)
	le.PutUint16(buf[25:27], uint16(p.Flags))
	le.PutUint32(buf[27:31], p.ChunkSize)
	le.PutUint64(buf[31:39], p.DurationMS)
	le.PutUint64(buf[39:47], p.WarmupMS)
	copy(buf[47:63], p.NonceClient[:])
	return buf, nil
}

func NewHello(transport FloTransport, id ulid.ULID, security FloSecurity, direction protocol.FloDir, chunkSize uint32, duration, warmup time.Duration) (*PktHello, error) {
	var pkt PktHello

	pkt.Header = createHeader(TypeHello)

	nonce, err := utils.NewNonce()
	if err != nil {
		return nil, err
	}

	copy(pkt.SessionID[:], id[:])
	pkt.Transport = transport
	pkt.Security = security
	pkt.Direction = direction
	pkt.Flags = 0
	pkt.ChunkSize = chunkSize
	pkt.DurationMS = uint64(duration.Milliseconds())
	pkt.WarmupMS = uint64(warmup.Milliseconds())
	copy(pkt.NonceClient[:], nonce[:])

	return &pkt, nil
}
