package protocol

import (
	"sync/atomic"
	"time"
)

// Stats will keep track of total bytes sent and received during a test session
type Stats struct {
	bytesSent atomic.Uint64
	bytesRcvd atomic.Uint64
}

func (s *Stats) AddBytesSent(delta uint64) {
	s.bytesSent.Add(delta)
}

func (s *Stats) AddBytesRcvd(delta uint64) {
	s.bytesRcvd.Add(delta)
}

func (s *Stats) Reset() {
	s.bytesSent.Store(0)
	s.bytesRcvd.Store(0)
}

func (s *Stats) GetBytesSent() uint64 {
	return s.bytesSent.Load()
}

func (s *Stats) GetBytesRcvd() uint64 {
	return s.bytesRcvd.Load()
}

type StatsDiff struct {
	BytesSent uint64
	BytesRcvd uint64
	Duration  time.Duration
}
