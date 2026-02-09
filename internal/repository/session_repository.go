package repository

import (
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"

	"gorm.io/gorm"
)

type SessionRepository interface {
	Create(s *domain.Session) error
	FindValidByHash(hash string) (*domain.Session, error)
	RevokeByHash(hash string) error
	RevokeByUserID(userID uint) error
	CleanupExpired() (int64, error)
}

type GormSessionRepository struct{ db *gorm.DB }

func NewSessionRepository(db *gorm.DB) SessionRepository { return &GormSessionRepository{db: db} }

func (r *GormSessionRepository) Create(s *domain.Session) error { return r.db.Create(s).Error }

func (r *GormSessionRepository) FindValidByHash(hash string) (*domain.Session, error) {
	var s domain.Session
	err := r.db.Where("refresh_token_hash = ? AND revoked_at IS NULL AND expires_at > ?", hash, time.Now()).First(&s).Error
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *GormSessionRepository) RevokeByHash(hash string) error {
	now := time.Now()
	return r.db.Model(&domain.Session{}).Where("refresh_token_hash = ? AND revoked_at IS NULL", hash).Update("revoked_at", now).Error
}

func (r *GormSessionRepository) RevokeByUserID(userID uint) error {
	now := time.Now()
	return r.db.Model(&domain.Session{}).Where("user_id = ? AND revoked_at IS NULL", userID).Update("revoked_at", now).Error
}

func (r *GormSessionRepository) CleanupExpired() (int64, error) {
	res := r.db.Where("expires_at <= ?", time.Now()).Delete(&domain.Session{})
	return res.RowsAffected, res.Error
}
