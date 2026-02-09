package repository

import (
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"

	"gorm.io/gorm"
)

type PermissionRepository interface {
	List() ([]domain.Permission, error)
	FindByPairs(pairs [][2]string) ([]domain.Permission, error)
}

type GormPermissionRepository struct{ db *gorm.DB }

func NewPermissionRepository(db *gorm.DB) PermissionRepository {
	return &GormPermissionRepository{db: db}
}

func (r *GormPermissionRepository) List() ([]domain.Permission, error) {
	var perms []domain.Permission
	err := r.db.Find(&perms).Error
	return perms, err
}

func (r *GormPermissionRepository) FindByPairs(pairs [][2]string) ([]domain.Permission, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	q := r.db.Model(&domain.Permission{})
	for i, pair := range pairs {
		if i == 0 {
			q = q.Where("(resource = ? AND action = ?)", pair[0], pair[1])
		} else {
			q = q.Or("(resource = ? AND action = ?)", pair[0], pair[1])
		}
	}
	var perms []domain.Permission
	if err := q.Find(&perms).Error; err != nil {
		return nil, err
	}
	return perms, nil
}
