package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/goodieshq/goflo/internal/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).Level(zerolog.DebugLevel)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	port := uint16(1234)
	srv := server.NewServerTCP(server.ServerOpts{
		Host:               "",
		Port:               port,
		PSK:                []byte("Test1234"),
		Timeout:            time.Second * 3,
		MaxConcurrentTests: 2,
	})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info().Uint16("port", port).Msg("Starting GoFlo server")
		err := srv.Run(ctx)
		if err != nil {
			panic(err)
		} else {
			log.Info().Msg("GoFlo server stopped")
		}
	}()

	<-ctx.Done()
	wg.Wait()
}
