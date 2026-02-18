package database

import (
	"context"
	"time"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/observability"

	"gorm.io/gorm"
)

func Migrate(db *gorm.DB) error {
	start := time.Now()
	err := db.AutoMigrate(
		&domain.User{},
		&domain.LocalCredential{},
		&domain.Role{},
		&domain.Permission{},
		&domain.UserRole{},
		&domain.RolePermission{},
		&domain.OAuthAccount{},
		&domain.Session{},
		&domain.VerificationToken{},
		&domain.IdempotencyRecord{},
		&domain.FeatureFlag{},
		&domain.FeatureFlagRule{},
		&domain.Product{},
	)
	observability.RecordDatabaseStartupDuration(context.Background(), "migrate", time.Since(start))
	if err != nil {
		observability.RecordDatabaseStartupEvent(context.Background(), "migrate", "error")
		return err
	}
	observability.RecordDatabaseStartupEvent(context.Background(), "migrate", "success")
	return nil
}
