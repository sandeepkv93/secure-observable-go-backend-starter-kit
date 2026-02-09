package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
)

type roleView struct {
	ID          uint   `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type roleListPage struct {
	Items []roleView `json:"items"`
}

type syncReport struct {
	CreatedPermissions int  `json:"created_permissions"`
	CreatedRoles       int  `json:"created_roles"`
	BoundPermissions   int  `json:"bound_permissions"`
	Noop               bool `json:"noop"`
}

func TestAdminRBACProtectedRoleDeletionRejected(t *testing.T) {
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.BootstrapAdminEmail = "admin-rbac@example.com"
		},
	})
	defer closeFn()

	registerAndLogin(t, client, baseURL, "admin-rbac@example.com", "Valid#Pass1234")

	resp, env := doJSON(t, client, http.MethodGet, baseURL+"/api/v1/admin/roles", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("list roles failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	var roleData roleListPage
	if err := json.Unmarshal(env.Data, &roleData); err != nil {
		t.Fatalf("decode roles: %v", err)
	}
	var adminRoleID uint
	for _, role := range roleData.Items {
		if role.Name == "admin" {
			adminRoleID = role.ID
			break
		}
	}
	if adminRoleID == 0 {
		t.Fatal("expected admin role")
	}

	resp, env = doJSON(t, client, http.MethodDelete, baseURL+"/api/v1/admin/roles/"+itoa(adminRoleID), nil, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for protected role delete, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "FORBIDDEN" {
		t.Fatalf("expected FORBIDDEN, got %#v", env.Error)
	}
}

func TestAdminRBACPermissionConflict(t *testing.T) {
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.BootstrapAdminEmail = "admin-perm@example.com"
		},
	})
	defer closeFn()

	registerAndLogin(t, client, baseURL, "admin-perm@example.com", "Valid#Pass1234")

	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/admin/permissions", map[string]string{
		"resource": "users",
		"action":   "read",
	}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 duplicate permission, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "CONFLICT" {
		t.Fatalf("expected CONFLICT, got %#v", env.Error)
	}
}

func TestAdminRBACSyncIdempotent(t *testing.T) {
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.BootstrapAdminEmail = "admin-sync@example.com"
		},
	})
	defer closeFn()

	registerAndLogin(t, client, baseURL, "admin-sync@example.com", "Valid#Pass1234")

	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/admin/rbac/sync", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("first sync failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	var first syncReport
	if err := json.Unmarshal(env.Data, &first); err != nil {
		t.Fatalf("decode first sync: %v", err)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/admin/rbac/sync", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("second sync failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	var second syncReport
	if err := json.Unmarshal(env.Data, &second); err != nil {
		t.Fatalf("decode second sync: %v", err)
	}

	if !second.Noop || second.CreatedPermissions != 0 || second.CreatedRoles != 0 || second.BoundPermissions != 0 {
		t.Fatalf("expected second sync noop with zero diff, got %+v", second)
	}
	_ = first
}

func itoa(v uint) string { return fmt.Sprintf("%d", v) }
