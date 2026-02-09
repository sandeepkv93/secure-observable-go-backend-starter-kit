package repository

import (
	"errors"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"gorm.io/gorm"
)

var ErrVerificationTokenNotFound = errors.New("verification token not found")

type VerificationTokenRepository interface {
	Create(token *domain.VerificationToken) error
	InvalidateActiveByUserPurpose(userID uint, purpose string, now time.Time) error
	FindActiveByHashPurpose(hash, purpose string, now time.Time) (*domain.VerificationToken, error)
	Consume(tokenID, userID uint, now time.Time) error
}

type GormVerificationTokenRepository struct {
	db *gorm.DB
}

func NewVerificationTokenRepository(db *gorm.DB) VerificationTokenRepository {
	return &GormVerificationTokenRepository{db: db}
}

func (r *GormVerificationTokenRepository) Create(token *domain.VerificationToken) error {
	return r.db.Create(token).Error
}

func (r *GormVerificationTokenRepository) InvalidateActiveByUserPurpose(userID uint, purpose string, now time.Time) error {
	return r.db.Model(&domain.VerificationToken{}).
		Where("user_id = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?", userID, purpose, now).
		Updates(map[string]any{"used_at": now, "updated_at": now}).Error
}

func (r *GormVerificationTokenRepository) FindActiveByHashPurpose(hash, purpose string, now time.Time) (*domain.VerificationToken, error) {
	var token domain.VerificationToken
	err := r.db.Where("token_hash = ? AND purpose = ? AND used_at IS NULL AND expires_at > ?", hash, purpose, now).
		First(&token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrVerificationTokenNotFound
		}
		return nil, err
	}
	return &token, nil
}

func (r *GormVerificationTokenRepository) Consume(tokenID, userID uint, now time.Time) error {
	res := r.db.Model(&domain.VerificationToken{}).
		Where("id = ? AND user_id = ? AND used_at IS NULL", tokenID, userID).
		Updates(map[string]any{"used_at": now, "updated_at": now})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrVerificationTokenNotFound
	}
	return nil
}
