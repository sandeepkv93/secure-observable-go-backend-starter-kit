package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type DBIdempotencyStore struct {
	db *gorm.DB
}

func NewDBIdempotencyStore(db *gorm.DB) *DBIdempotencyStore {
	return &DBIdempotencyStore{db: db}
}

func (s *DBIdempotencyStore) CleanupExpired(ctx context.Context, now time.Time, batchSize int) (int64, error) {
	if batchSize <= 0 {
		batchSize = 500
	}
	scoped := s.db.WithContext(ctx)
	sub := scoped.Model(&domain.IdempotencyRecord{}).
		Select("id").
		Where("expires_at <= ?", now.UTC()).
		Order("id ASC").
		Limit(batchSize)
	res := scoped.
		Where("id IN (?)", sub).
		Delete(&domain.IdempotencyRecord{})
	if res.Error != nil {
		observability.RecordIdempotencyCleanupRun(ctx, "error")
		return res.RowsAffected, res.Error
	}
	observability.RecordIdempotencyCleanupRun(ctx, "success")
	observability.RecordIdempotencyCleanupDeletedRows(ctx, res.RowsAffected)
	return res.RowsAffected, res.Error
}

func (s *DBIdempotencyStore) RunCleanupLoop(ctx context.Context, interval time.Duration, batchSize int, logger *slog.Logger) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := s.CleanupExpired(ctx, time.Now().UTC(), batchSize)
			if err != nil {
				if logger != nil {
					logger.Warn("idempotency db cleanup failed", "error", err)
				}
				continue
			}
			if deleted > 0 && logger != nil {
				logger.Info("idempotency db cleanup removed expired records", "deleted", deleted)
			}
		}
	}
}

func (s *DBIdempotencyStore) Begin(ctx context.Context, scope, key, fingerprint string, ttl time.Duration) (IdempotencyBeginResult, error) {
	now := time.Now().UTC()
	var result IdempotencyBeginResult
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var rec domain.IdempotencyRecord
		err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("scope = ? AND idempotency_key = ?", scope, key).
			First(&rec).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				create := domain.IdempotencyRecord{
					Scope:           scope,
					IdempotencyKey:  key,
					FingerprintHash: fingerprint,
					Status:          string(IdempotencyStateNew),
					ExpiresAt:       now.Add(ttl),
				}
				if createErr := tx.Create(&create).Error; createErr != nil {
					if isUniqueConstraintErr(createErr) {
						return retryableReadConflict(createErr)
					}
					return createErr
				}
				result.State = IdempotencyStateNew
				return nil
			}
			return err
		}

		if rec.ExpiresAt.Before(now) {
			rec.FingerprintHash = fingerprint
			rec.Status = string(IdempotencyStateNew)
			rec.ResponseStatus = 0
			rec.ResponseBody = nil
			rec.ContentType = ""
			rec.ExpiresAt = now.Add(ttl)
			if saveErr := tx.Save(&rec).Error; saveErr != nil {
				return saveErr
			}
			result.State = IdempotencyStateNew
			return nil
		}

		if rec.FingerprintHash != fingerprint {
			result.State = IdempotencyStateConflict
			return nil
		}
		if rec.Status == "completed" {
			result.State = IdempotencyStateReplay
			result.Cached = &CachedHTTPResponse{
				StatusCode:  rec.ResponseStatus,
				ContentType: rec.ContentType,
				Body:        append([]byte(nil), rec.ResponseBody...),
			}
			return nil
		}
		result.State = IdempotencyStateInProgress
		return nil
	})
	if err != nil {
		if errors.Is(err, errRetryableReadConflict) {
			return s.Begin(ctx, scope, key, fingerprint, ttl)
		}
		return IdempotencyBeginResult{}, err
	}
	return result, nil
}

func (s *DBIdempotencyStore) Complete(ctx context.Context, scope, key, fingerprint string, response CachedHTTPResponse, ttl time.Duration) error {
	now := time.Now().UTC()
	res := s.db.WithContext(ctx).Model(&domain.IdempotencyRecord{}).
		Where("scope = ? AND idempotency_key = ? AND fingerprint_hash = ?", scope, key, fingerprint).
		Where("status <> ?", "completed").
		Updates(map[string]any{
			"status":          "completed",
			"response_status": response.StatusCode,
			"response_body":   response.Body,
			"content_type":    response.ContentType,
			"expires_at":      now.Add(ttl),
		})
	return res.Error
}

var errRetryableReadConflict = errors.New("retryable read conflict")

func retryableReadConflict(err error) error {
	if err == nil {
		return nil
	}
	return errRetryableReadConflict
}

func isUniqueConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "unique constraint") ||
		strings.Contains(lower, "duplicate key") ||
		strings.Contains(lower, "unique violation")
}
