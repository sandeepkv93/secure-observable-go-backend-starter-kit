package repository

import (
	"errors"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"gorm.io/gorm"
)

var ErrPermissionNotFound = errors.New("permission not found")

type PermissionRepository interface {
	List() ([]domain.Permission, error)
	ListPaged(req PageRequest, sortBy, sortOrder, resource, action string) (PageResult[domain.Permission], error)
	FindByID(id uint) (*domain.Permission, error)
	FindByPairs(pairs [][2]string) ([]domain.Permission, error)
	FindByResourceAction(resource, action string) (*domain.Permission, error)
	Create(permission *domain.Permission) error
	Update(permission *domain.Permission) error
	DeleteByID(id uint) error
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

func (r *GormPermissionRepository) ListPaged(req PageRequest, sortBy, sortOrder, resource, action string) (PageResult[domain.Permission], error) {
	normalized := normalizePageRequest(req)
	result := PageResult[domain.Permission]{
		Page:     normalized.Page,
		PageSize: normalized.PageSize,
	}

	base := r.db.Model(&domain.Permission{})
	if resource != "" {
		base = base.Where("permissions.resource LIKE ?", resource+"%")
	}
	if action != "" {
		base = base.Where("permissions.action LIKE ?", action+"%")
	}
	if err := base.Count(&result.Total).Error; err != nil {
		return PageResult[domain.Permission]{}, err
	}

	query := base
	if sortBy != "" {
		query = query.Order("permissions." + sortBy + " " + sortOrder)
	}
	query = query.Order("permissions.id " + sortOrder)
	offset := (normalized.Page - 1) * normalized.PageSize
	if err := query.Offset(offset).Limit(normalized.PageSize).Find(&result.Items).Error; err != nil {
		return PageResult[domain.Permission]{}, err
	}
	result.TotalPages = calcTotalPages(result.Total, normalized.PageSize)
	return result, nil
}

func (r *GormPermissionRepository) FindByID(id uint) (*domain.Permission, error) {
	var p domain.Permission
	if err := r.db.First(&p, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPermissionNotFound
		}
		return nil, err
	}
	return &p, nil
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

func (r *GormPermissionRepository) FindByResourceAction(resource, action string) (*domain.Permission, error) {
	var p domain.Permission
	if err := r.db.Where("resource = ? AND action = ?", resource, action).First(&p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrPermissionNotFound
		}
		return nil, err
	}
	return &p, nil
}

func (r *GormPermissionRepository) Create(permission *domain.Permission) error {
	return r.db.Create(permission).Error
}

func (r *GormPermissionRepository) Update(permission *domain.Permission) error {
	res := r.db.Model(&domain.Permission{}).Where("id = ?", permission.ID).Updates(map[string]any{
		"resource": permission.Resource,
		"action":   permission.Action,
	})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrPermissionNotFound
	}
	return nil
}

func (r *GormPermissionRepository) DeleteByID(id uint) error {
	res := r.db.Delete(&domain.Permission{}, id)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrPermissionNotFound
	}
	return nil
}
