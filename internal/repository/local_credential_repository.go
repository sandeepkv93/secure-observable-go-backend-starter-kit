package repository

import (
	"strings"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"

	"gorm.io/gorm"
)

type LocalCredentialRepository interface {
	Create(credential *domain.LocalCredential) error
	FindByUserID(userID uint) (*domain.LocalCredential, error)
	FindByEmail(email string) (*domain.LocalCredential, error)
	UpdatePassword(userID uint, newHash string) error
	MarkEmailVerified(userID uint) error
}

type GormLocalCredentialRepository struct {
	db *gorm.DB
}

func NewLocalCredentialRepository(db *gorm.DB) LocalCredentialRepository {
	return &GormLocalCredentialRepository{db: db}
}

func (r *GormLocalCredentialRepository) Create(credential *domain.LocalCredential) error {
	return r.db.Create(credential).Error
}

func (r *GormLocalCredentialRepository) FindByUserID(userID uint) (*domain.LocalCredential, error) {
	var c domain.LocalCredential
	if err := r.db.Where("user_id = ?", userID).First(&c).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *GormLocalCredentialRepository) FindByEmail(email string) (*domain.LocalCredential, error) {
	var c domain.LocalCredential
	normalized := strings.TrimSpace(strings.ToLower(email))
	err := r.db.
		Joins("JOIN users ON users.id = local_credentials.user_id").
		Where("users.email = ?", normalized).
		First(&c).Error
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *GormLocalCredentialRepository) UpdatePassword(userID uint, newHash string) error {
	return r.db.Model(&domain.LocalCredential{}).Where("user_id = ?", userID).
		Updates(map[string]any{"password_hash": newHash, "updated_at": time.Now().UTC()}).Error
}

func (r *GormLocalCredentialRepository) MarkEmailVerified(userID uint) error {
	now := time.Now().UTC()
	return r.db.Model(&domain.LocalCredential{}).Where("user_id = ?", userID).
		Updates(map[string]any{"email_verified": true, "email_verified_at": &now, "updated_at": now}).Error
}
