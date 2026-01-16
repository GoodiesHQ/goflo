package packets

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/goodieshq/goflo/internal/protocol"
	"github.com/oklog/ulid/v2"
)

const (
	TypeHello     protocol.FloType = 1 // Initiate connection
	TypeChallenge protocol.FloType = 2 // Server challenge for authentication (if auth enabled)
	TypeAnswer    protocol.FloType = 3 // Client challenge answer
	TypeAck       protocol.FloType = 4 // Acknowledgment packet
	TypeResult    protocol.FloType = 5 // Result packet (for download requests)
)

func PacketTypeToString(t protocol.FloType) string {
	switch t {
	case TypeHello:
		return "HELLO"
	case TypeChallenge:
		return "CHALLENGE"
	case TypeAnswer:
		return "ANSWER"
	case TypeAck:
		return "ACK"
	case TypeResult:
		return "RESULT"
	default:
		return "UNKNOWN"
	}
}

// Authentication methods available
type FloAuth uint8

const (
	AuthNone FloAuth = 0 // no authentication required
	AuthHMAC FloAuth = 1 // HMAC-based authentication
)

// Transport + optional wrapping protocol to use
type FloTransport uint8

const (
	TransportTCP  FloTransport = 1
	TransportUDP  FloTransport = 2
	TransportSCTP FloTransport = 3
)

// Security protocol to use (if any)
type FloSecurity uint8

const (
	SecurityNone FloSecurity = 0
	SecurityTLS  FloSecurity = 1
)

type FloAckCode uint8

const (
	AckOK             FloAckCode = 0 // Acknowledgment OK, proceed with test
	AckInvalidVersion FloAckCode = 1 // Flo protocol version not supported
	AckInvalidHello   FloAckCode = 2 // Malformed Hello packet
	AckAuthFailed     FloAckCode = 3 // Authentication failed
	AckBusy           FloAckCode = 4 // Server is busy / cannot accept new connections
)

// Flags for additional options (placeholder for future use)
type FloFlags uint16

const (
// FloFlags reserved for future use
)

var le = binary.LittleEndian

/* AuthHash is computed as HMAC_SHA256(HELLO_PACKET || NONCE_SERVER, SHARED_SECRET) */

// Compute the authentication hash from raw hello packet bytes and server nonce
func ComputeAuthHash(helloPktBytes []byte, nonceServer [16]byte, psk []byte) [32]byte {
	h := hmac.New(sha256.New, psk)
	h.Write(helloPktBytes)
	h.Write(nonceServer[:])

	var result [32]byte
	copy(result[:], h.Sum(nil)[:])
	return result
}

// Compute the authentication hash from a Hello packet and server nonce
func ComputeAuthHashPacket(helloPkt *PktHello, nonceServer [16]byte, psk []byte) ([32]byte, error) {
	helloBytes, err := helloPkt.Marshal()
	if err != nil {
		return [32]byte{}, err
	}
	return ComputeAuthHash(helloBytes, nonceServer, psk), nil
}

// Verify the received authentication hash against expected value
func VerifyAuthHash(helloPktBytes []byte, nonceServer [16]byte, psk []byte, receivedHash [32]byte) bool {
	expectedHash := ComputeAuthHash(helloPktBytes, nonceServer, psk)
	return hmac.Equal(expectedHash[:], receivedHash[:])
}

func SendPacket(w *bufio.Writer, pkt protocol.Packet) ([]byte, error) {
	// marshal the packet into bytes
	buf, err := pkt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal packet: %w", err)
	}

	_, err = w.Write(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to send packet: %w", err)
	}

	err = w.Flush()
	if err != nil {
		return nil, fmt.Errorf("failed to flush packet: %w", err)
	}

	return buf, nil
}

type Session struct {
	id   ulid.ULID
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
}

func NewSession(id ulid.ULID, conn net.Conn, r *bufio.Reader, w *bufio.Writer) *Session {
	if r == nil {
		r = bufio.NewReader(conn)
	}
	if w == nil {
		w = bufio.NewWriter(conn)
	}

	return &Session{id, conn, r, w}
}

func (s *Session) Close() error {
	return s.conn.Close()
}
