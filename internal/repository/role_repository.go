package repository

import (
	"errors"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"gorm.io/gorm"
)

var ErrRoleNotFound = errors.New("role not found")

type RoleRepository interface {
	FindByID(id uint) (*domain.Role, error)
	FindByName(name string) (*domain.Role, error)
	List() ([]domain.Role, error)
	ListPaged(req PageRequest, sortBy, sortOrder, name string) (PageResult[domain.Role], error)
	Create(role *domain.Role, permissionIDs []uint) error
	Update(role *domain.Role, permissionIDs []uint) error
	DeleteByID(id uint) error
}

type GormRoleRepository struct{ db *gorm.DB }

func NewRoleRepository(db *gorm.DB) RoleRepository { return &GormRoleRepository{db: db} }

func (r *GormRoleRepository) FindByID(id uint) (*domain.Role, error) {
	var role domain.Role
	err := r.db.Preload("Permissions").First(&role, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return &role, nil
}

func (r *GormRoleRepository) FindByName(name string) (*domain.Role, error) {
	var role domain.Role
	err := r.db.Preload("Permissions").Where("name = ?", name).First(&role).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRoleNotFound
		}
		return nil, err
	}
	return &role, nil
}

func (r *GormRoleRepository) List() ([]domain.Role, error) {
	var roles []domain.Role
	err := r.db.Preload("Permissions").Find(&roles).Error
	return roles, err
}

func (r *GormRoleRepository) ListPaged(req PageRequest, sortBy, sortOrder, name string) (PageResult[domain.Role], error) {
	normalized := normalizePageRequest(req)
	result := PageResult[domain.Role]{
		Page:     normalized.Page,
		PageSize: normalized.PageSize,
	}

	base := r.db.Model(&domain.Role{})
	if name != "" {
		base = base.Where("roles.name LIKE ?", name+"%")
	}
	if err := base.Count(&result.Total).Error; err != nil {
		return PageResult[domain.Role]{}, err
	}

	query := base.Preload("Permissions")
	if sortBy != "" {
		query = query.Order("roles." + sortBy + " " + sortOrder)
	}
	query = query.Order("roles.id " + sortOrder)
	offset := (normalized.Page - 1) * normalized.PageSize
	if err := query.Offset(offset).Limit(normalized.PageSize).Find(&result.Items).Error; err != nil {
		return PageResult[domain.Role]{}, err
	}
	result.TotalPages = calcTotalPages(result.Total, normalized.PageSize)
	return result, nil
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

func (r *GormRoleRepository) Update(role *domain.Role, permissionIDs []uint) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		var existing domain.Role
		if err := tx.Preload("Permissions").First(&existing, role.ID).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrRoleNotFound
			}
			return err
		}
		if err := tx.Model(&existing).Updates(map[string]any{
			"name":        role.Name,
			"description": role.Description,
		}).Error; err != nil {
			return err
		}
		var perms []domain.Permission
		if len(permissionIDs) > 0 {
			if err := tx.Where("id IN ?", permissionIDs).Find(&perms).Error; err != nil {
				return err
			}
		}
		return tx.Model(&existing).Association("Permissions").Replace(perms)
	})
}

func (r *GormRoleRepository) DeleteByID(id uint) error {
	res := r.db.Delete(&domain.Role{}, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrRoleNotFound
	}
	return nil
}
