package transfer

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/goodieshq/goflo/internal/protocol/packets/v1"
	"github.com/goodieshq/goflo/internal/utils"
	"github.com/rs/zerolog/log"
)

func SendLoop(ctx context.Context, w io.Writer, chunkSize uint32, stats *packets.Stats, counting *atomic.Bool) error {
	buf := make([]byte, chunkSize)
	for i := 0; i < int(chunkSize); i++ {
		buf[i] = byte(i)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := w.Write(buf)
		if n > 0 && counting.Load() {
			stats.AddBytesSent(uint64(n))
		}
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return err
		}
	}
}

func RecvLoop(ctx context.Context, r io.Reader, chunkSize uint32, stats *packets.Stats, counting *atomic.Bool) error {
	buf := make([]byte, chunkSize)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := r.Read(buf)
		if n > 0 && counting.Load() {
			stats.AddBytesRcvd(uint64(n))
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			return err
		}
	}
}

func Logger(ctx context.Context, stats *packets.Stats, counting *atomic.Bool, warmup time.Duration) {
	if warmup > 0 {
		log.Info().Msgf("Warming up for %s", warmup)
	}
	<-time.After(warmup)
	counting.Store(true)

	tick := time.NewTicker(1 * time.Second)
	defer tick.Stop()
	t := time.Now()

	var lastBytesSent uint64 = 0
	var lastBytesRcvd uint64 = 0

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			bytesSent := stats.GetBytesSent()
			bytesRcvd := stats.GetBytesRcvd()

			now := time.Now()
			diffSent := bytesSent - lastBytesSent
			diffRcvd := bytesRcvd - lastBytesRcvd
			diffTime := now.Sub(t)
			t = now

			lastBytesSent = bytesSent
			lastBytesRcvd = bytesRcvd

			evt := log.Info()
			if diffSent > 0 {
				evt = evt.Str("sent", utils.DisplayBPS(diffSent, diffTime))
			}
			if diffRcvd > 0 {
				evt = evt.Str("rcvd", utils.DisplayBPS(diffRcvd, diffTime))
			}
			evt.Msg("Throughput stats")
		}
	}
}

func TransferData(ctx context.Context, conn net.Conn, r *bufio.Reader, w *bufio.Writer, chunkSize uint32, duration, warmup time.Duration, stats *packets.Stats) error {
	// Clear deadline during data transfer
	conn.SetDeadline(time.Time{})

	totalTime := duration + warmup

	// Create a cancellable context for transfer loops
	ctx, cancel := context.WithTimeout(ctx, totalTime)
	defer cancel()

	var counting atomic.Bool

	count := 0
	if r != nil {
		count++
	}
	if w != nil {
		count++
	}

	errCh := make(chan error, count)

	// Start the logger goroutine to periodically log stats
	go Logger(ctx, stats, &counting, warmup)

	// Start both send and recv transfer loops
	if w != nil {
		go func() { errCh <- SendLoop(ctx, w, chunkSize, stats, &counting) }()
	}
	if r != nil {
		go func() { errCh <- RecvLoop(ctx, r, chunkSize, stats, &counting) }()
	}

	select {
	case <-ctx.Done():
	case err := <-errCh:
		_ = err
		cancel()
	}
	if w != nil {
		_ = w.Flush()
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}

	select {
	case <-ctx.Done():
		if ctx.Err() == context.Canceled {
			log.Warn().Msg("Transfer was canceled prematurely")
		}
		return nil
	case <-time.After(totalTime):
		log.Warn().Msg("Transfer exceeded duration")
		return nil
	}
}
