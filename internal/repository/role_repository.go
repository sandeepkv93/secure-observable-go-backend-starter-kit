package repository

import (
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"

	"gorm.io/gorm"
)

type RoleRepository interface {
	FindByName(name string) (*domain.Role, error)
	List() ([]domain.Role, error)
	Create(role *domain.Role, permissionIDs []uint) error
}

type GormRoleRepository struct{ db *gorm.DB }

func NewRoleRepository(db *gorm.DB) RoleRepository { return &GormRoleRepository{db: db} }

func (r *GormRoleRepository) FindByName(name string) (*domain.Role, error) {
	var role domain.Role
	err := r.db.Preload("Permissions").Where("name = ?", name).First(&role).Error
	if err != nil {
		return nil, err
	}
	return &role, nil
}

func (r *GormRoleRepository) List() ([]domain.Role, error) {
	var roles []domain.Role
	err := r.db.Preload("Permissions").Find(&roles).Error
	return roles, err
}

func (r *GormRoleRepository) Create(role *domain.Role, permissionIDs []uint) error {
	if err := r.db.Create(role).Error; err != nil {
		return err
	}
	if len(permissionIDs) == 0 {
		return nil
	}
	var perms []domain.Permission
	if err := r.db.Where("id IN ?", permissionIDs).Find(&perms).Error; err != nil {
		return err
	}
	return r.db.Model(role).Association("Permissions").Replace(perms)
}
