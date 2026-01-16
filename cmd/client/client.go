package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/goodieshq/goflo/internal/client"
	"github.com/goodieshq/goflo/internal/protocol"
	"github.com/goodieshq/goflo/internal/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Create a new TCP client
	cli := client.NewClientTCP(
		"localhost",              // host
		1234,                     // port
		[]byte("Test1234"),       // pre-shared key
		utils.Ptr(1*time.Second), // timeout
	)

	// Run the client with specified options
	err := cli.Run(ctx, client.RunOpts{
		Duration:  utils.Ptr(10 * time.Second),
		Warmup:    utils.Ptr(2 * time.Second),
		ChunkSize: utils.Ptr(uint32(1024 * 8)), // 8KiB
		Direction: utils.Ptr(protocol.DirectionDownload),
	})
	if err != nil {
		log.Error().Err(err).Msg("Client error")
	}
}
