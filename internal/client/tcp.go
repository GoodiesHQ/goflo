package client

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

type ClientTCP struct {
	host        string
	port        uint16
	psk         []byte
	authEnabled bool
	timeout     time.Duration
}

func NewClientTCP(
	host string,
	port uint16,
	psk []byte,
	timeout *time.Duration,
) *ClientTCP {
	t := utils.DefaultIfNil(timeout, 3*time.Second)
	return &ClientTCP{
		host:        host,
		port:        port,
		psk:         psk,
		authEnabled: len(psk) > 0,
		timeout:     t,
	}
}

// recvHeader reads and unmarshals a packet header from the connection
func (c *ClientTCP) recvHeader(conn net.Conn, r *bufio.Reader) (*protocol.Header, []byte, error) {
	conn.SetReadDeadline(time.Now().Add(c.timeout))

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

// recvChallengeV1 reads and unmarshals a Challenge packet from the server
func (c *ClientTCP) recvChallengeV1(conn net.Conn, r *bufio.Reader, bufHeader []byte) (*packets.PktChallenge, []byte, error) {
	conn.SetReadDeadline(time.Now().Add(c.timeout))

	bufChallenge, err := utils.ReadExact(r, packets.PktChallengeSize-protocol.HeaderSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read challenge packet: %w", err)
	}
	bufChallenge = append(bufHeader, bufChallenge...)

	pktChallenge, err := packets.UnmarshalChallenge(bufChallenge)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal challenge packet: %w", err)
	}

	return pktChallenge, bufChallenge, nil
}

// recvAckV1 reads and unmarshals an Ack packet from the server
func (c *ClientTCP) recvAckV1(conn net.Conn, r *bufio.Reader, bufHeader []byte) (*packets.PktAck, []byte, error) {
	conn.SetReadDeadline(time.Now().Add(c.timeout))

	bufAck, err := utils.ReadExact(r, packets.PktAckSize-protocol.HeaderSize)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read ack packet: %w", err)
	}
	bufAck = append(bufHeader, bufAck...)

	pktAck, err := packets.UnmarshalAck(bufAck)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal ack packet: %w", err)
	}

	return pktAck, bufAck, nil
}

// sendHelloV1 sends a Hello packet to the server and returns the raw bytes sent
func (c *ClientTCP) sendHelloV1(conn net.Conn, w *bufio.Writer, sessionId ulid.ULID, direction protocol.FloDir, chunkSize uint32, duration, warmup time.Duration) (*packets.PktHello, []byte, error) {
	conn.SetWriteDeadline(time.Now().Add(c.timeout))

	// Send Hello packet to server
	pktHello, err := packets.NewHello(
		packets.TransportTCP,
		sessionId,
		packets.SecurityNone,
		direction,
		chunkSize,
		duration,
		warmup,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create hello packet: %w", err)
	}

	bufHello, err := packets.SendPacket(w, pktHello)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send hello packet: %w", err)
	}
	log.Debug().Msg("Hello packet sent")

	return pktHello, bufHello, nil
}

// sendAnswerV1 sends an Answer packet to the server in response to a Challenge
func (c *ClientTCP) sendAnswerV1(conn net.Conn, w *bufio.Writer, sessionId ulid.ULID, hash [32]byte) (*packets.PktAnswer, []byte, error) {
	conn.SetWriteDeadline(time.Now().Add(c.timeout))

	pktAnswer, err := packets.NewAnswer(sessionId, hash)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create answer packet: %w", err)
	}

	bufAnswer, err := packets.SendPacket(w, pktAnswer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send answer packet: %w", err)
	}

	log.Debug().Msg("Answer packet sent")
	return pktAnswer, bufAnswer, nil
}

// RunOpts defines options for running the client
func (c *ClientTCP) Run(ctx context.Context, runOpts RunOpts) error {
	address := net.JoinHostPort(c.host, fmt.Sprintf("%d", c.port))
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	defer conn.Close()

	// generate a ULID for this session
	sessionId, err := utils.NewULID()
	if err != nil {
		return fmt.Errorf("failed to generate session ID: %w", err)
	}

	// set up buffered reader and writer
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	// send hello packet to server
	pktHello, bufHello, err := c.sendHelloV1(
		conn,
		w,
		sessionId,
		runOpts.GetDirection(),
		runOpts.GetChunkSize(),
		runOpts.GetDuration(),
		runOpts.GetWarmup(),
	)
	if err != nil {
		return fmt.Errorf("failed to send hello packet: %w", err)
	}

	// read the response header from the server
	pktHeader, bufHeader, err := c.recvHeader(conn, r)
	if err != nil {
		return fmt.Errorf("failed to receive packet header: %w", err)
	}

	// Handle server response based on packet type
	var pktAck *packets.PktAck

	switch pktHeader.Type {
	case packets.TypeChallenge:
		// receive Challenge packet from server
		pktChallenge, _, err := c.recvChallengeV1(conn, r, bufHeader)
		if err != nil {
			return fmt.Errorf("failed to receive challenge packet: %w", err)
		}

		// commpute auth hash from challenge and psk
		hash := packets.ComputeAuthHash(bufHello, pktChallenge.NonceServer, c.psk)

		// send Answer packet to server
		_, _, err = c.sendAnswerV1(conn, w, sessionId, hash)
		if err != nil {
			return fmt.Errorf("failed to send answer packet: %w", err)
		}

		// receive Ack packet from server
		pktHeader, bufHeader, err := c.recvHeader(conn, r)
		if err != nil {
			return fmt.Errorf("failed to receive packet header: %w", err)
		}

		if pktHeader.Type != packets.TypeAck {
			return fmt.Errorf("expected Ack packet, got type: %d", pktHeader.Type)
		}

		pktAck, _, err = c.recvAckV1(conn, r, bufHeader)
		if err != nil {
			return fmt.Errorf("failed to receive ack packet: %w", err)
		}

	case packets.TypeAck:
		pktAck, _, err = c.recvAckV1(conn, r, bufHeader)
		if err != nil {
			return fmt.Errorf("failed to receive ack packet: %w", err)
		}
	default:
		return fmt.Errorf("unexpected packet type: %d", pktHeader.Type)
	}

	switch pktAck.Code {
	case packets.AckAuthFailed:
		return fmt.Errorf("authentication failed: incorrect preshared key")
	case packets.AckBusy:
		return fmt.Errorf("server is busy: max concurrent tests reached")
	case packets.AckOK:
		// proceed
	default:
		return fmt.Errorf("received unexpected ack code: %d", pktAck.Code)
	}

	log.Info().Msg("Connected to server successfully, beginning throughput test")

	duration := time.Duration(pktHello.DurationMS) * time.Millisecond
	warmup := time.Duration(pktHello.WarmupMS) * time.Millisecond

	var stats packets.Stats
	switch runOpts.GetDirection() {
	case protocol.DirectionBidi:
		err = transfer.TransferData(ctx, conn, r, w, pktHello.ChunkSize, duration, warmup, &stats)
		if err != nil {
			return fmt.Errorf("data transfer failed: %w", err)
		}
	case protocol.DirectionUpload:
		err = transfer.TransferData(ctx, conn, nil, w, pktHello.ChunkSize, duration, warmup, &stats)
		if err != nil {
			return fmt.Errorf("data send failed: %w", err)
		}
	case protocol.DirectionDownload:
		err = transfer.TransferData(ctx, conn, r, nil, pktHello.ChunkSize, duration, warmup, &stats)
		if err != nil {
			return fmt.Errorf("data receive failed: %w", err)
		}
	default:
		return fmt.Errorf("invalid direction: %d", pktHello.Direction)
	}

	_ = w.Flush()

	sessionIdStr := sessionId.String()
	evt := log.Info().Str("session_id", sessionIdStr)
	if stats.GetBytesSent() > 0 {
		evt = evt.Str("total_sent", utils.DisplayB(stats.GetBytesSent())).
			Str("avg_sent", utils.DisplayBPS(stats.GetBytesSent(), duration))
	}
	if stats.GetBytesRcvd() > 0 {
		evt = evt.Str("total_rcvd", utils.DisplayB(stats.GetBytesRcvd())).
			Str("avg_rcvd", utils.DisplayBPS(stats.GetBytesRcvd(), duration))
	}
	evt.Msg("Data transfer complete")

	return nil
}
