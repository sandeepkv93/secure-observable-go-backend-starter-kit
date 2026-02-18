package repository

import (
	"errors"
	"fmt"
	"testing"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
)

func TestProductRepositoryCRUDAndPagination(t *testing.T) {
	db := newRepositoryDBForTest(t)
	if err := db.AutoMigrate(&domain.Product{}); err != nil {
		t.Fatalf("migrate product: %v", err)
	}
	repo := NewProductRepository(db)

	created := make([]*domain.Product, 0, 3)
	for i := 0; i < 3; i++ {
		p := &domain.Product{Name: fmt.Sprintf("Product %c", 'A'+i), Description: "desc", Price: float64(10 + i)}
		if err := repo.Create(p); err != nil {
			t.Fatalf("create product %d: %v", i, err)
		}
		created = append(created, p)
	}

	page, err := repo.ListPaged(PageRequest{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("list paged: %v", err)
	}
	if page.Total != 3 || page.TotalPages != 2 || len(page.Items) != 2 {
		t.Fatalf("unexpected page result: %+v", page)
	}
	if page.Items[0].ID != created[2].ID {
		t.Fatalf("expected latest product first, got id=%d want=%d", page.Items[0].ID, created[2].ID)
	}

	loaded, err := repo.FindByID(created[0].ID)
	if err != nil {
		t.Fatalf("find by id: %v", err)
	}
	if loaded.Name != created[0].Name {
		t.Fatalf("name mismatch: got %q want %q", loaded.Name, created[0].Name)
	}

	if err := repo.Update(created[0].ID, map[string]any{"name": "Renamed", "price": 99.5}); err != nil {
		t.Fatalf("update: %v", err)
	}
	updated, err := repo.FindByID(created[0].ID)
	if err != nil {
		t.Fatalf("find updated: %v", err)
	}
	if updated.Name != "Renamed" || updated.Price != 99.5 {
		t.Fatalf("unexpected updated product: %+v", updated)
	}

	if err := repo.DeleteByID(created[1].ID); err != nil {
		t.Fatalf("delete by id: %v", err)
	}
	if _, err := repo.FindByID(created[1].ID); !errors.Is(err, ErrProductNotFound) {
		t.Fatalf("expected not found after delete, got %v", err)
	}
}

func TestProductRepositoryNotFoundCases(t *testing.T) {
	db := newRepositoryDBForTest(t)
	if err := db.AutoMigrate(&domain.Product{}); err != nil {
		t.Fatalf("migrate product: %v", err)
	}
	repo := NewProductRepository(db)

	if _, err := repo.FindByID(999); !errors.Is(err, ErrProductNotFound) {
		t.Fatalf("expected ErrProductNotFound, got %v", err)
	}
	if err := repo.Update(999, map[string]any{"name": "x"}); !errors.Is(err, ErrProductNotFound) {
		t.Fatalf("expected ErrProductNotFound on update, got %v", err)
	}
	if err := repo.DeleteByID(999); !errors.Is(err, ErrProductNotFound) {
		t.Fatalf("expected ErrProductNotFound on delete, got %v", err)
	}
}
