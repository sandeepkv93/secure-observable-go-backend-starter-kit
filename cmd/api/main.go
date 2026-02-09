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

	totalTimeout := a.ShutdownTimeout
	if totalTimeout <= 0 {
		totalTimeout = 20 * time.Second
	}
	totalCtx, totalCancel := context.WithTimeout(context.Background(), totalTimeout)
	defer totalCancel()

	httpTimeout := a.ShutdownHTTPDrainTimeout
	if httpTimeout <= 0 {
		httpTimeout = 10 * time.Second
	}
	httpCtx, httpCancel := context.WithTimeout(totalCtx, httpTimeout)
	if err := a.Server.Shutdown(httpCtx); err != nil {
		a.Logger.Error("failed to shutdown http server", "error", err)
	}
	httpCancel()

	if a.Observability != nil {
		obsTimeout := a.ShutdownObservabilityTimeout
		if obsTimeout <= 0 {
			obsTimeout = 8 * time.Second
		}
		obsCtx, obsCancel := context.WithTimeout(totalCtx, obsTimeout)
		if err := a.Observability.Shutdown(obsCtx); err != nil {
			a.Logger.Error("failed to shutdown observability", "error", err)
		}
		obsCancel()
	}

	if a.Redis != nil {
		if err := a.Redis.Close(); err != nil {
			a.Logger.Error("failed to close redis client", "error", err)
		}
	}
	if a.DB != nil {
		if sqlDB, err := a.DB.DB(); err == nil {
			if err := sqlDB.Close(); err != nil {
				a.Logger.Error("failed to close database connection", "error", err)
			}
		}
	}
}
