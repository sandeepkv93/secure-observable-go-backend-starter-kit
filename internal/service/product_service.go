package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
)

var (
	ErrProductInvalidName        = errors.New("name must be between 3 and 120 characters")
	ErrProductInvalidDescription = errors.New("description must be <= 500 characters")
	ErrProductInvalidPrice       = errors.New("price must be greater than 0")
	ErrProductNoUpdates          = errors.New("no updates provided")
)

type CreateProductInput struct {
	Name        string
	Description string
	Price       float64
}

type UpdateProductInput struct {
	Name        *string
	Description *string
	Price       *float64
}

type ProductServiceImpl struct {
	repo repository.ProductRepository
}

func NewProductService(repo repository.ProductRepository) *ProductServiceImpl {
	return &ProductServiceImpl{repo: repo}
}

func (s *ProductServiceImpl) Create(ctx context.Context, input CreateProductInput) (*domain.Product, error) {
	start := time.Now()
	outcome := "success"
	defer func() { observability.RecordProductOperation(ctx, "create", outcome, time.Since(start)) }()

	name := strings.TrimSpace(input.Name)
	description := strings.TrimSpace(input.Description)
	if len(name) < 3 || len(name) > 120 {
		outcome = "bad_request"
		return nil, ErrProductInvalidName
	}
	if len(description) > 500 {
		outcome = "bad_request"
		return nil, ErrProductInvalidDescription
	}
	if input.Price <= 0 {
		outcome = "bad_request"
		return nil, ErrProductInvalidPrice
	}

	product := &domain.Product{Name: name, Description: description, Price: input.Price}
	if err := s.repo.Create(product); err != nil {
		outcome = "error"
		return nil, err
	}
	return product, nil
}

func (s *ProductServiceImpl) ListPaged(ctx context.Context, req repository.PageRequest) (repository.PageResult[domain.Product], error) {
	start := time.Now()
	outcome := "success"
	defer func() { observability.RecordProductOperation(ctx, "list", outcome, time.Since(start)) }()

	res, err := s.repo.ListPaged(req)
	if err != nil {
		outcome = "error"
		return repository.PageResult[domain.Product]{}, err
	}
	return res, nil
}

func (s *ProductServiceImpl) GetByID(ctx context.Context, id uint) (*domain.Product, error) {
	start := time.Now()
	outcome := "success"
	defer func() { observability.RecordProductOperation(ctx, "get", outcome, time.Since(start)) }()

	product, err := s.repo.FindByID(id)
	if err != nil {
		if errors.Is(err, repository.ErrProductNotFound) {
			outcome = "not_found"
		} else {
			outcome = "error"
		}
		return nil, err
	}
	return product, nil
}

func (s *ProductServiceImpl) Update(ctx context.Context, id uint, input UpdateProductInput) (*domain.Product, error) {
	start := time.Now()
	outcome := "success"
	defer func() { observability.RecordProductOperation(ctx, "update", outcome, time.Since(start)) }()

	updates := map[string]any{}
	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		if len(name) < 3 || len(name) > 120 {
			outcome = "bad_request"
			return nil, ErrProductInvalidName
		}
		updates["name"] = name
	}
	if input.Description != nil {
		description := strings.TrimSpace(*input.Description)
		if len(description) > 500 {
			outcome = "bad_request"
			return nil, ErrProductInvalidDescription
		}
		updates["description"] = description
	}
	if input.Price != nil {
		if *input.Price <= 0 {
			outcome = "bad_request"
			return nil, ErrProductInvalidPrice
		}
		updates["price"] = *input.Price
	}
	if len(updates) == 0 {
		outcome = "bad_request"
		return nil, ErrProductNoUpdates
	}

	if err := s.repo.Update(id, updates); err != nil {
		if errors.Is(err, repository.ErrProductNotFound) {
			outcome = "not_found"
		} else {
			outcome = "error"
		}
		return nil, err
	}
	product, err := s.repo.FindByID(id)
	if err != nil {
		outcome = "error"
		return nil, err
	}
	return product, nil
}

func (s *ProductServiceImpl) DeleteByID(ctx context.Context, id uint) error {
	start := time.Now()
	outcome := "success"
	defer func() { observability.RecordProductOperation(ctx, "delete", outcome, time.Since(start)) }()

	if err := s.repo.DeleteByID(id); err != nil {
		if errors.Is(err, repository.ErrProductNotFound) {
			outcome = "not_found"
		} else {
			outcome = "error"
		}
		return err
	}
	return nil
}
