package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func InstallSignalHandler() (context.Context, func()) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	subctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-quit
		cancel()
	}()

	return subctx, cancel
}
