package transfer

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/goodieshq/goflo/internal/protocol"
	"github.com/goodieshq/goflo/internal/utils"
	"github.com/rs/zerolog/log"
)

func SendLoop(ctx context.Context, w io.Writer, chunkSize uint32, stats *protocol.Stats, counting *atomic.Bool) error {
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

func RecvLoop(ctx context.Context, r io.Reader, chunkSize uint32, stats *protocol.Stats, counting *atomic.Bool) error {
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
				return err
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

func Reporter(ctx context.Context, statsCh chan<- protocol.StatsDiff, stats *protocol.Stats, counting *atomic.Bool, warmup time.Duration) {
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

			statsCh <- protocol.StatsDiff{
				BytesSent: diffSent,
				BytesRcvd: diffRcvd,
				Duration:  diffTime,
			}
		}
	}
}

func Logger(ctx context.Context, statsCh chan protocol.StatsDiff, stats *protocol.Stats, counting *atomic.Bool, warmup time.Duration) {
	go Reporter(ctx, statsCh, stats, counting, warmup)

	for {
		diff := <-statsCh
		evt := log.Info()
		if diff.BytesSent > 0 {
			evt = evt.Str("sent", utils.DisplayBitsPerTime(diff.BytesSent, diff.Duration))
		}
		if diff.BytesRcvd > 0 {
			evt = evt.Str("rcvd", utils.DisplayBitsPerTime(diff.BytesRcvd, diff.Duration))
		}
		evt.Msg("Throughput stats")
	}
}

func TransferData(ctx context.Context, conn net.Conn, r *bufio.Reader, w *bufio.Writer, chunkSize uint32, duration, warmup time.Duration, stats *protocol.Stats) error {
	// Clear deadline during data transfer
	_ = conn.SetDeadline(time.Time{})

	totalTime := duration + warmup

	// Create a cancellable context for transfer loops
	ctx, cancel := context.WithTimeout(ctx, totalTime)
	defer cancel()

	deadline, deadlineOk := ctx.Deadline()
	var counting atomic.Bool

	count := 0
	if r != nil {
		count++
	}
	if w != nil {
		count++
	}

	errCh := make(chan error, count)
	statsCh := make(chan protocol.StatsDiff)

	// Start the logger goroutine to periodically log stats
	go Logger(ctx, statsCh, stats, &counting, warmup)

	// Start both send and recv transfer loops
	if w != nil {
		go func() { errCh <- SendLoop(ctx, w, chunkSize, stats, &counting) }()
	}
	if r != nil {
		go func() { errCh <- RecvLoop(ctx, r, chunkSize, stats, &counting) }()
	}

	var errStop error
	// Wait for either either timeout or an error from one of the loops
	select {
	case <-ctx.Done():
		errStop = ctx.Err()
	case err := <-errCh:
		errStop = err
		cancel()
	}

	// Half-close the connection if possible
	if w != nil {
		_ = w.Flush()
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}

	// drain the remaining goroutine results
	for i := 1; i < count; i++ {
		select {
		case <-errCh:
		case <-time.After(100 * time.Millisecond):
		}
	}

	const grace = 250 * time.Millisecond

	remaining := time.Duration(0)
	if deadlineOk {
		remaining = time.Until(deadline)
	}

	var premature bool
	switch {
	case errStop == nil:
		premature = false
	case errors.Is(errStop, context.DeadlineExceeded):
		premature = false
	case errors.Is(errStop, io.EOF):
		if deadlineOk && remaining > grace {
			premature = true
		}
	default:
		if !(deadlineOk && remaining <= grace) {
			premature = true
		}
	}

	if premature {
		log.Warn().Err(errStop).Msg("Transfer ended early (disconnected)")
	}

	return nil
}
