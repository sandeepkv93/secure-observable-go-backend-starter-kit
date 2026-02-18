package service

import (
	"context"
	"errors"
	"testing"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
)

type stubProductRepo struct {
	items  map[uint]domain.Product
	nextID uint
}

func (s *stubProductRepo) Create(product *domain.Product) error {
	if s.items == nil {
		s.items = map[uint]domain.Product{}
	}
	if s.nextID == 0 {
		s.nextID = 1
	}
	product.ID = s.nextID
	s.nextID++
	s.items[product.ID] = *product
	return nil
}

func (s *stubProductRepo) FindByID(id uint) (*domain.Product, error) {
	product, ok := s.items[id]
	if !ok {
		return nil, repository.ErrProductNotFound
	}
	cp := product
	return &cp, nil
}

func (s *stubProductRepo) ListPaged(req repository.PageRequest) (repository.PageResult[domain.Product], error) {
	normalized := repository.PageRequest{Page: req.Page, PageSize: req.PageSize}
	if normalized.Page < 1 {
		normalized.Page = repository.DefaultPage
	}
	if normalized.PageSize < 1 {
		normalized.PageSize = repository.DefaultPageSize
	}
	items := make([]domain.Product, 0, len(s.items))
	for _, p := range s.items {
		items = append(items, p)
	}
	total := int64(len(items))
	return repository.PageResult[domain.Product]{
		Items:      items,
		Page:       normalized.Page,
		PageSize:   normalized.PageSize,
		Total:      total,
		TotalPages: 1,
	}, nil
}

func (s *stubProductRepo) Update(id uint, updates map[string]any) error {
	product, ok := s.items[id]
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
	s.items[id] = product
	return nil
}

func (s *stubProductRepo) DeleteByID(id uint) error {
	if _, ok := s.items[id]; !ok {
		return repository.ErrProductNotFound
	}
	delete(s.items, id)
	return nil
}

func TestProductServiceValidation(t *testing.T) {
	svc := NewProductService(&stubProductRepo{items: map[uint]domain.Product{}})

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
	repo := &stubProductRepo{items: map[uint]domain.Product{}}
	svc := NewProductService(repo)

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
