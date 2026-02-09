package service

import (
	"testing"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
)

func TestRBACPermissionEvaluation(t *testing.T) {
	svc := NewRBACService()
	roles := []domain.Role{{Name: "admin", Permissions: []domain.Permission{{Resource: "users", Action: "read"}, {Resource: "roles", Action: "write"}}}}
	perms := svc.PermissionsFromRoles(roles)
	if !svc.HasPermission(perms, "users:read") {
		t.Fatal("expected users:read")
	}
	if svc.HasPermission(perms, "users:write") {
		t.Fatal("did not expect users:write")
	}
}
