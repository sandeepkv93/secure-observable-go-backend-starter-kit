package repository

import (
	"context"
	"errors"

	"gorm.io/gorm"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/observability"
)

var ErrProductNotFound = errors.New("product not found")

type ProductRepository interface {
	Create(product *domain.Product) error
	FindByID(id uint) (*domain.Product, error)
	ListPaged(req PageRequest) (PageResult[domain.Product], error)
	Update(id uint, updates map[string]any) error
	DeleteByID(id uint) error
}

type GormProductRepository struct{ db *gorm.DB }

func NewProductRepository(db *gorm.DB) ProductRepository {
	return &GormProductRepository{db: db}
}

func (r *GormProductRepository) Create(product *domain.Product) error {
	if err := r.db.Create(product).Error; err != nil {
		observability.RecordRepositoryOperation(context.Background(), "product", "create", "error")
		return err
	}
	observability.RecordRepositoryOperation(context.Background(), "product", "create", "success")
	return nil
}

func (r *GormProductRepository) FindByID(id uint) (*domain.Product, error) {
	var product domain.Product
	if err := r.db.First(&product, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			observability.RecordRepositoryOperation(context.Background(), "product", "find_by_id", "not_found")
			return nil, ErrProductNotFound
		}
		observability.RecordRepositoryOperation(context.Background(), "product", "find_by_id", "error")
		return nil, err
	}
	observability.RecordRepositoryOperation(context.Background(), "product", "find_by_id", "success")
	return &product, nil
}

func (r *GormProductRepository) ListPaged(req PageRequest) (PageResult[domain.Product], error) {
	normalized := normalizePageRequest(req)
	result := PageResult[domain.Product]{
		Page:     normalized.Page,
		PageSize: normalized.PageSize,
	}

	base := r.db.Model(&domain.Product{})
	if err := base.Count(&result.Total).Error; err != nil {
		observability.RecordRepositoryOperation(context.Background(), "product", "list_paged", "error")
		return PageResult[domain.Product]{}, err
	}
	offset := (normalized.Page - 1) * normalized.PageSize
	if err := base.Order("id desc").Offset(offset).Limit(normalized.PageSize).Find(&result.Items).Error; err != nil {
		observability.RecordRepositoryOperation(context.Background(), "product", "list_paged", "error")
		return PageResult[domain.Product]{}, err
	}
	result.TotalPages = calcTotalPages(result.Total, normalized.PageSize)
	observability.RecordRepositoryOperation(context.Background(), "product", "list_paged", "success")
	return result, nil
}

func (r *GormProductRepository) Update(id uint, updates map[string]any) error {
	res := r.db.Model(&domain.Product{}).Where("id = ?", id).Updates(updates)
	if res.Error != nil {
		observability.RecordRepositoryOperation(context.Background(), "product", "update", "error")
		return res.Error
	}
	if res.RowsAffected == 0 {
		observability.RecordRepositoryOperation(context.Background(), "product", "update", "not_found")
		return ErrProductNotFound
	}
	observability.RecordRepositoryOperation(context.Background(), "product", "update", "success")
	return nil
}

func (r *GormProductRepository) DeleteByID(id uint) error {
	res := r.db.Delete(&domain.Product{}, id)
	if res.Error != nil {
		observability.RecordRepositoryOperation(context.Background(), "product", "delete_by_id", "error")
		return res.Error
	}
	if res.RowsAffected == 0 {
		observability.RecordRepositoryOperation(context.Background(), "product", "delete_by_id", "not_found")
		return ErrProductNotFound
	}
	observability.RecordRepositoryOperation(context.Background(), "product", "delete_by_id", "success")
	return nil
}
