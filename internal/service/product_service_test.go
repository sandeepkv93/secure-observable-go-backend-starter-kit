package service

import (
	"context"
	"errors"
	"testing"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
	repogomock "github.com/sandeepkv93/everything-backend-starter-kit/internal/repository/gomock"
	"go.uber.org/mock/gomock"
)

func TestProductServiceValidation(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := repogomock.NewMockProductRepository(ctrl)
	svc := NewProductService(repo)

	_, err := svc.Create(context.Background(), CreateProductInput{Name: "ab", Price: 10})
	if !errors.Is(err, ErrProductInvalidName) {
		t.Fatalf("expected ErrProductInvalidName, got %v", err)
	}

	_, err = svc.Create(context.Background(), CreateProductInput{Name: "Valid Name", Price: 0})
	if !errors.Is(err, ErrProductInvalidPrice) {
		t.Fatalf("expected ErrProductInvalidPrice, got %v", err)
	}

	longDescription := make([]byte, 501)
	for i := range longDescription {
		longDescription[i] = 'a'
	}
	_, err = svc.Create(context.Background(), CreateProductInput{Name: "Valid Name", Description: string(longDescription), Price: 10})
	if !errors.Is(err, ErrProductInvalidDescription) {
		t.Fatalf("expected ErrProductInvalidDescription, got %v", err)
	}

	name := "ok"
	_, err = svc.Update(context.Background(), 1, UpdateProductInput{Name: &name})
	if !errors.Is(err, ErrProductInvalidName) {
		t.Fatalf("expected ErrProductInvalidName on update, got %v", err)
	}

	_, err = svc.Update(context.Background(), 1, UpdateProductInput{})
	if !errors.Is(err, ErrProductNoUpdates) {
		t.Fatalf("expected ErrProductNoUpdates, got %v", err)
	}
}

func TestProductServiceCRUDFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := repogomock.NewMockProductRepository(ctrl)
	svc := NewProductService(repo)

	items := map[uint]domain.Product{}
	nextID := uint(1)

	repo.EXPECT().Create(gomock.AssignableToTypeOf(&domain.Product{})).DoAndReturn(func(product *domain.Product) error {
		product.ID = nextID
		nextID++
		items[product.ID] = *product
		return nil
	})
	repo.EXPECT().FindByID(gomock.Any()).DoAndReturn(func(id uint) (*domain.Product, error) {
		product, ok := items[id]
		if !ok {
			return nil, repository.ErrProductNotFound
		}
		cp := product
		return &cp, nil
	}).Times(3)
	repo.EXPECT().Update(gomock.Any(), gomock.Any()).DoAndReturn(func(id uint, updates map[string]any) error {
		product, ok := items[id]
		if !ok {
			return repository.ErrProductNotFound
		}
		if v, ok := updates["name"].(string); ok {
			product.Name = v
		}
		if v, ok := updates["description"].(string); ok {
			product.Description = v
		}
		if v, ok := updates["price"].(float64); ok {
			product.Price = v
		}
		items[id] = product
		return nil
	})
	repo.EXPECT().ListPaged(gomock.Any()).DoAndReturn(func(req repository.PageRequest) (repository.PageResult[domain.Product], error) {
		normalized := repository.PageRequest{Page: req.Page, PageSize: req.PageSize}
		if normalized.Page < 1 {
			normalized.Page = repository.DefaultPage
		}
		if normalized.PageSize < 1 {
			normalized.PageSize = repository.DefaultPageSize
		}
		out := make([]domain.Product, 0, len(items))
		for _, p := range items {
			out = append(out, p)
		}
		return repository.PageResult[domain.Product]{
			Items:      out,
			Page:       normalized.Page,
			PageSize:   normalized.PageSize,
			Total:      int64(len(out)),
			TotalPages: 1,
		}, nil
	})
	repo.EXPECT().DeleteByID(gomock.Any()).DoAndReturn(func(id uint) error {
		if _, ok := items[id]; !ok {
			return repository.ErrProductNotFound
		}
		delete(items, id)
		return nil
	})

	created, err := svc.Create(context.Background(), CreateProductInput{Name: "Sample Product", Description: "desc", Price: 12.5})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	loaded, err := svc.GetByID(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	if loaded.Name != "Sample Product" {
		t.Fatalf("unexpected loaded product: %+v", loaded)
	}

	name := "Updated Product"
	price := 18.75
	updated, err := svc.Update(context.Background(), created.ID, UpdateProductInput{Name: &name, Price: &price})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Updated Product" || updated.Price != 18.75 {
		t.Fatalf("unexpected updated product: %+v", updated)
	}

	page, err := svc.ListPaged(context.Background(), repository.PageRequest{})
	if err != nil {
		t.Fatalf("list paged: %v", err)
	}
	if page.Total != 1 {
		t.Fatalf("expected total 1, got %d", page.Total)
	}

	if err := svc.DeleteByID(context.Background(), created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.GetByID(context.Background(), created.ID); !errors.Is(err, repository.ErrProductNotFound) {
		t.Fatalf("expected not found after delete, got %v", err)
	}
}
