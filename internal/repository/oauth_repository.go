package repository

import (
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"

	"gorm.io/gorm"
)

type OAuthRepository interface {
	FindByProvider(provider, providerUserID string) (*domain.OAuthAccount, error)
	Create(account *domain.OAuthAccount) error
}

type GormOAuthRepository struct{ db *gorm.DB }

func NewOAuthRepository(db *gorm.DB) OAuthRepository { return &GormOAuthRepository{db: db} }

func (r *GormOAuthRepository) FindByProvider(provider, providerUserID string) (*domain.OAuthAccount, error) {
	var a domain.OAuthAccount
	err := r.db.Where("provider = ? AND provider_user_id = ?", provider, providerUserID).First(&a).Error
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (r *GormOAuthRepository) Create(account *domain.OAuthAccount) error {
	return r.db.Create(account).Error
}
