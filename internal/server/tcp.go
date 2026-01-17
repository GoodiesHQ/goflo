package server

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"time"

	"github.com/goodieshq/goflo/internal/protocol"
	"github.com/goodieshq/goflo/internal/protocol/packets/v1"
	"github.com/goodieshq/goflo/internal/protocol/transfer"
	"github.com/goodieshq/goflo/internal/utils"
	"github.com/oklog/ulid/v2"
	"github.com/rs/zerolog/log"
)

type ServerTCP struct {
	host        string
	port        uint16
	psk         []byte
	authEnabled bool
	timeout     time.Duration
	slots       chan struct{}
}

type ServerOpts struct {
	Host               string
	Port               uint16
	PSK                []byte
	Timeout            time.Duration
	MaxConcurrentTests uint32
}

func NewServerTCP(opts ServerOpts) *ServerTCP {
	if opts.Timeout == 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.MaxConcurrentTests <= 0 {
		opts.MaxConcurrentTests = 1
	}

	slots := make(chan struct{}, opts.MaxConcurrentTests)
	for i := uint32(0); i < opts.MaxConcurrentTests; i++ {
		slots <- struct{}{}
	}

	return &ServerTCP{
		host:        opts.Host,         // server listening host
		port:        opts.Port,         // server listening port
		psk:         opts.PSK,          // pre-shared key for HMAC authentication
		authEnabled: len(opts.PSK) > 0, // enable auth if PSK is provided
		timeout:     opts.Timeout,      // read/write timeout
		slots:       slots,             // semaphore for max concurrent tests
	}
}

func (s *ServerTCP) slotAcquire() bool {
	select {
	case <-s.slots:
		return true
	default:
		return false
	}
}

func (s *ServerTCP) slotRelease() {
	s.slots <- struct{}{}
}

// recvHeader reads and unmarshals a packet header from the connection
func (s *ServerTCP) recvHeader(conn net.Conn, r *bufio.Reader) (*protocol.Header, []byte, error) {
	conn.SetReadDeadline(time.Now().Add(s.timeout))

	bufHeader, err := utils.ReadExact(r, protocol.HeaderSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read packet header: %w", err)
	}

	header, err := protocol.UnmarshalHeader(bufHeader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal packet header: %w", err)
	}

	return header, bufHeader, nil
}

// Run starts the TCP server and listens for incoming connections
func (s *ServerTCP) Run(ctx context.Context) error {
	address := fmt.Sprintf("%s:%d", s.host, s.port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	defer listener.Close()
	go func() {
		// Shutdown server listener on context cancellation
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // server is shutting down
			}
			fmt.Printf("failed to accept connection: %v\n", err)
			continue
		}
		log.Debug().Str("remote_addr", conn.RemoteAddr().String()).Msg("Accepted new connection")
		go func() {
			err := s.handle(ctx, conn)
			if err != nil {
				log.Error().Err(err).Msg("Connection handler error")
			}
		}()
	}
}

// handle processes an individual client connection
func (s *ServerTCP) handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	// Set up buffered reader and writer
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	defer w.Flush()

	log.Debug().Msg("Set connection deadline")

	// Read and parse packet header
	header, headerBuf, err := s.recvHeader(conn, r)
	if err != nil {
		return fmt.Errorf("failed to read packet header: %w", err)
	}
	log.Debug().Msgf("Received header")

	log.Debug().
		Uint8("version", uint8(header.Version)).
		Str("type", packets.PacketTypeToString(header.Type)).
		Msgf("Parsed header")

	// handle based on protocol version
	switch header.Version {
	case protocol.FloVersion1:
		return s.handleV1(ctx, conn, r, w, headerBuf, header)
	default:
		return protocol.ErrUnsupportedVersion
	}
}

// sendAckV1 creates and sends an Ack packet to the client
func (s *ServerTCP) sendAckV1(conn net.Conn, w *bufio.Writer, sessionID ulid.ULID, auth packets.FloAuth, code packets.FloAckCode) error {
	conn.SetWriteDeadline(time.Now().Add(s.timeout))

	// create and send ack packet
	pktAck, err := packets.NewAck(sessionID, auth, code)
	if err != nil {
		return fmt.Errorf("failed to create ack packet: %w", err)
	}

	_, err = packets.SendPacket(w, pktAck)
	if err != nil {
		return fmt.Errorf("failed to send ack packet: %w", err)
	}

	return nil
}

// sendChallengeV1 creates and sends a Challenge packet to the client
func (s *ServerTCP) sendChallengeV1(conn net.Conn, w *bufio.Writer, sessionID ulid.ULID, nonceServer [16]byte) (*packets.PktChallenge, error) {
	conn.SetWriteDeadline(time.Now().Add(s.timeout))

	pktChallenge, err := packets.NewChallenge(sessionID, packets.AuthHMAC, nonceServer)
	if err != nil {
		return nil, fmt.Errorf("failed to create challenge packet: %w", err)
	}

	_, err = packets.SendPacket(w, pktChallenge)
	if err != nil {
		return nil, fmt.Errorf("failed to send challenge packet: %w", err)
	}

	log.Debug().Str("session_id", pktChallenge.SessionID.String()).Msg("Challenge packet sent")
	return pktChallenge, nil
}

// recvAnswerV1 reads and unmarshals an Answer packet from the client
func (s *ServerTCP) recvAnswerV1(conn net.Conn, r *bufio.Reader, bufHeader []byte) (*packets.PktAnswer, []byte, error) {
	conn.SetReadDeadline(time.Now().Add(s.timeout))

	bufAnswer, err := utils.ReadExact(r, packets.PktAnswerSize-protocol.HeaderSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read answer packet: %w", err)
	}
	bufAnswer = append(bufHeader, bufAnswer...)

	pktAnswer, err := packets.UnmarshalAnswer(bufAnswer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal answer packet: %w", err)
	}

	return pktAnswer, bufAnswer, nil
}

// handleAuthV1 performs the authentication handshake with the client
func (s *ServerTCP) handleAuthV1(conn net.Conn, r *bufio.Reader, w *bufio.Writer, bufHello []byte, pktHello *packets.PktHello) (bool, error) {
	// generate server nonce
	nonceServer, err := utils.NewNonce()
	if err != nil {
		return false, fmt.Errorf("failed to generate server nonce: %w", err)
	}

	pktChallenge, err := s.sendChallengeV1(conn, w, pktHello.SessionID, nonceServer)
	if err != nil {
		return false, fmt.Errorf("failed to send challenge packet: %w", err)
	}

	header, bufHeader, err := s.recvHeader(conn, r)
	if err != nil {
		return false, fmt.Errorf("failed to read answer packet header: %w", err)
	}

	if header.Version != protocol.FloVersion1 {
		return false, fmt.Errorf("unsupported protocol version in answer packet: %d", header.Version)
	}

	if header.Type != packets.TypeAnswer {
		return false, protocol.ErrIncorrectType
	}

	pktAnswer, _, err := s.recvAnswerV1(conn, r, bufHeader)
	if err != nil {
		return false, fmt.Errorf("failed to receive answer packet: %w", err)
	}

	// verify the expected auth hash
	verified := packets.VerifyAuthHash(bufHello, nonceServer, s.psk, pktAnswer.AuthHash)
	if !verified {
		log.Warn().Str("session_id", pktChallenge.SessionID.String()).Msg("Authentication failed: invalid auth hash")
	} else {
		log.Info().Str("session_id", pktChallenge.SessionID.String()).Msg("Client authenticated successfully")
	}

	return verified, nil
}

// recvHelloV1 reads and unmarshals a Hello packet from the client
func (s *ServerTCP) recvHelloV1(conn net.Conn, r *bufio.Reader, bufHeader []byte) (*packets.PktHello, []byte, error) {
	conn.SetReadDeadline(time.Now().Add(s.timeout))

	bufHello, err := utils.ReadExact(r, packets.PktHelloSize-protocol.HeaderSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read hello packet: %w", err)
	}
	bufHello = append(bufHeader, bufHello...)

	pktHello, err := packets.UnmarshalHello(bufHello)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal hello packet: %w", err)
	}

	return pktHello, bufHello, nil
}

// handleV1 processes a FLO v1 connection
func (s *ServerTCP) handleV1(ctx context.Context, conn net.Conn, r *bufio.Reader, w *bufio.Writer, bufHeader []byte, header *protocol.Header) error {
	// Handle FLO v1 connection
	if header.Type != packets.TypeHello {
		return protocol.ErrIncorrectType
	}

	// read the rest of the hello packet and re-assemble
	pktHello, bufHello, err := s.recvHelloV1(conn, r, bufHeader)

	// perform authentication if it is enabled on the server
	auth := packets.AuthNone
	if s.authEnabled {
		auth = packets.AuthHMAC
		authenticated, err := s.handleAuthV1(conn, r, w, bufHello, pktHello)
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}

		if !authenticated {
			err := s.sendAckV1(conn, w, pktHello.SessionID, auth, packets.AckAuthFailed)
			if err != nil {
				return fmt.Errorf("failed to send auth failed ack: %w", err)
			}
			return protocol.ErrAuthFailed
		}
	}

	if s.slotAcquire() == false {
		err := s.sendAckV1(conn, w, pktHello.SessionID, auth, packets.AckBusy)
		if err != nil {
			return fmt.Errorf("failed to send busy ack: %w", err)
		}
		return fmt.Errorf("server is busy: max concurrent tests reached")
	}
	defer s.slotRelease()

	err = s.sendAckV1(conn, w, pktHello.SessionID, auth, packets.AckOK)
	if err != nil {
		return fmt.Errorf("failed to send ok ack: %w", err)
	}

	duration := time.Duration(pktHello.DurationMS) * time.Millisecond
	warmup := time.Duration(pktHello.WarmupMS) * time.Millisecond

	var stats protocol.Stats
	var t = time.Now()

	switch pktHello.Direction {
	case protocol.DirectionBidi:
		err = transfer.TransferData(ctx, conn, r, w, pktHello.ChunkSize, duration, warmup, &stats)
		if err != nil {
			return fmt.Errorf("data transfer failed: %w", err)
		}
	case protocol.DirectionUpload:
		err = transfer.TransferData(ctx, conn, r, nil, pktHello.ChunkSize, duration, warmup, &stats)
		if err != nil {
			return fmt.Errorf("data receive failed: %w", err)
		}
	case protocol.DirectionDownload:
		err = transfer.TransferData(ctx, conn, nil, w, pktHello.ChunkSize, duration, warmup, &stats)
		if err != nil {
			return fmt.Errorf("data send failed: %w", err)
		}
	default:
		return fmt.Errorf("invalid direction: %d", pktHello.Direction)
	}

	_ = w.Flush()

	durationReal := time.Since(t) - warmup
	if durationReal < 0 {
		durationReal = 0
	}

	sessionIdStr := pktHello.SessionID.String()
	evt := log.Info().Str("session_id", sessionIdStr)
	evt = evt.Str("duration", utils.DisplayTime(durationReal))
	if stats.GetBytesSent() > 0 {
		evt = evt.Str("total_sent", utils.DisplayBytes(stats.GetBytesSent())).
			Str("avg_sent", utils.DisplayBitsPerTime(stats.GetBytesSent(), durationReal))
	}
	if stats.GetBytesRcvd() > 0 {
		evt = evt.Str("total_rcvd", utils.DisplayBytes(stats.GetBytesRcvd())).
			Str("avg_rcvd", utils.DisplayBitsPerTime(stats.GetBytesRcvd(), durationReal))
	}
	evt.Msg("Client data transfer complete")

	return nil
}
