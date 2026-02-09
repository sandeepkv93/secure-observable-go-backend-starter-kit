package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/di"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		runner, err := di.InitializeMigrationRunner()
		if err != nil {
			log.Fatal(err)
		}
		if err := runner.Run(); err != nil {
			log.Fatal(err)
		}
		return
	}
	a, err := di.InitializeApp()
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		a.Logger.Info("server starting", "addr", a.Server.Addr)
		if err := a.Server.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
			log.Fatal(err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if a.Observability != nil {
		if err := a.Observability.Shutdown(ctx); err != nil {
			a.Logger.Error("failed to shutdown observability", "error", err)
		}
	}
	_ = a.Server.Shutdown(ctx)
}
