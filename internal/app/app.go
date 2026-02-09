package app

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/health"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
	"gorm.io/gorm"
)

type App struct {
	Config        *config.Config
	Logger        *slog.Logger
	Server        *http.Server
	Observability *observability.Runtime
	DB            *gorm.DB
	Redis         redis.UniversalClient
	Readiness     *health.ProbeRunner

	ShutdownTimeout              time.Duration
	ShutdownHTTPDrainTimeout     time.Duration
	ShutdownObservabilityTimeout time.Duration
}

func New(cfg *config.Config, logger *slog.Logger, server *http.Server, runtime *observability.Runtime, db *gorm.DB, redis redis.UniversalClient, readiness *health.ProbeRunner) *App {
	return &App{
		Config:                       cfg,
		Logger:                       logger,
		Server:                       server,
		Observability:                runtime,
		DB:                           db,
		Redis:                        redis,
		Readiness:                    readiness,
		ShutdownTimeout:              cfg.ShutdownTimeout,
		ShutdownHTTPDrainTimeout:     cfg.ShutdownHTTPDrainTimeout,
		ShutdownObservabilityTimeout: cfg.ShutdownObservabilityTimeout,
	}
}
