package database

import (
	"context"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func Open(cfg *config.Config) (*gorm.DB, error) {
	start := time.Now()
	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Warn),
	})
	observability.RecordDatabaseStartupDuration(context.Background(), "open", time.Since(start))
	if err != nil {
		observability.RecordDatabaseStartupEvent(context.Background(), "open", "error")
		return nil, err
	}
	observability.RecordDatabaseStartupEvent(context.Background(), "open", "success")
	return db, nil
}
