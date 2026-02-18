package service

import (
	"errors"
	"testing"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	repogomock "github.com/sandeepkv93/everything-backend-starter-kit/internal/repository/gomock"
	"go.uber.org/mock/gomock"
)

func TestUserServiceGetByID(t *testing.T) {
	t.Run("repo error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := repogomock.NewMockUserRepository(ctrl)
		expected := errors.New("db down")
		repo.EXPECT().FindByID(uint(1)).Return(nil, expected)
		svc := NewUserService(repo, NewRBACService())

		u, perms, err := svc.GetByID(1)
		if !errors.Is(err, expected) {
			t.Fatalf("expected %v, got %v", expected, err)
		}
		if u != nil || perms != nil {
			t.Fatal("expected nil user and perms on error")
		}
	})

	t.Run("success derives deduplicated permissions", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := repogomock.NewMockUserRepository(ctrl)
		repo.EXPECT().FindByID(uint(7)).Return(&domain.User{
			ID:    7,
			Email: "user@example.com",
			Roles: []domain.Role{
				{Name: "viewer", Permissions: []domain.Permission{{Resource: "users", Action: "read"}, {Resource: "roles", Action: "read"}}},
				{Name: "admin", Permissions: []domain.Permission{{Resource: "users", Action: "read"}, {Resource: "roles", Action: "write"}}},
			},
		}, nil)
		svc := NewUserService(repo, NewRBACService())

		u, perms, err := svc.GetByID(7)
		if err != nil {
			t.Fatalf("GetByID: %v", err)
		}
		if u == nil || u.ID != 7 {
			t.Fatalf("unexpected user: %+v", u)
		}
		if len(perms) != 3 {
			t.Fatalf("expected 3 deduplicated permissions, got %d (%v)", len(perms), perms)
		}
		assertPermissionSet(t, perms, []string{"users:read", "roles:read", "roles:write"})
	})
}

func TestUserServiceListDelegatesToRepo(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := repogomock.NewMockUserRepository(ctrl)
	repo.EXPECT().List().Return([]domain.User{{ID: 1, Email: "a@example.com"}, {ID: 2, Email: "b@example.com"}}, nil)
	svc := NewUserService(repo, NewRBACService())

	users, err := svc.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(users))
	}
}

func TestUserServiceListError(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := repogomock.NewMockUserRepository(ctrl)
	expected := errors.New("query failed")
	repo.EXPECT().List().Return(nil, expected)
	svc := NewUserService(repo, NewRBACService())

	_, err := svc.List()
	if !errors.Is(err, expected) {
		t.Fatalf("expected %v, got %v", expected, err)
	}
}

func TestUserServiceSetRolesDelegatesAndPropagatesErrors(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := repogomock.NewMockUserRepository(ctrl)
	svc := NewUserService(repo, NewRBACService())

	repo.EXPECT().SetRoles(uint(7), []uint{1, 2}).Return(nil)
	if err := svc.SetRoles(7, []uint{1, 2}); err != nil {
		t.Fatalf("SetRoles: %v", err)
	}

	expected := errors.New("replace failed")
	repo.EXPECT().SetRoles(uint(7), []uint{1, 2}).Return(expected)
	if err := svc.SetRoles(7, []uint{1, 2}); !errors.Is(err, expected) {
		t.Fatalf("expected %v, got %v", expected, err)
	}
}

func TestUserServiceAddRoleDelegatesAndPropagatesErrors(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := repogomock.NewMockUserRepository(ctrl)
	svc := NewUserService(repo, NewRBACService())

	repo.EXPECT().AddRole(uint(7), uint(3)).Return(nil)
	if err := svc.AddRole(7, 3); err != nil {
		t.Fatalf("AddRole: %v", err)
	}

	expected := errors.New("append failed")
	repo.EXPECT().AddRole(uint(7), uint(3)).Return(expected)
	if err := svc.AddRole(7, 3); !errors.Is(err, expected) {
		t.Fatalf("expected %v, got %v", expected, err)
	}
}

func assertPermissionSet(t *testing.T, got []string, expected []string) {
	t.Helper()
	set := make(map[string]struct{}, len(got))
	for _, p := range got {
		set[p] = struct{}{}
	}
	for _, want := range expected {
		if _, ok := set[want]; !ok {
			t.Fatalf("missing permission %q in %v", want, got)
		}
	}
}
