package client

import (
	"time"

	"github.com/goodieshq/goflo/internal/protocol"
	"github.com/goodieshq/goflo/internal/utils"
)

const (
	DEFAULT_DURATION   = 10 * time.Second
	DEFAULT_WARMUP     = 1 * time.Second
	DEFAULT_CHUNK_SIZE = 1024
	DEFAULT_DIRECTION  = protocol.DirectionBidi
)

type RunOpts struct {
	Direction *protocol.FloDir
	Duration  *time.Duration
	Warmup    *time.Duration
	ChunkSize *uint32
}

func (r RunOpts) GetDuration() time.Duration {
	return utils.DefaultIfNil(r.Duration, DEFAULT_DURATION)
}

func (r RunOpts) GetWarmup() time.Duration {
	return utils.DefaultIfNil(r.Warmup, DEFAULT_WARMUP)
}

func (r RunOpts) GetChunkSize() uint32 {
	return utils.DefaultIfNil(r.ChunkSize, DEFAULT_CHUNK_SIZE)
}

func (r RunOpts) GetDirection() protocol.FloDir {
	return utils.DefaultIfNil(r.Direction, DEFAULT_DIRECTION)
}

type Client interface {
	Run(opts RunOpts) error
}
