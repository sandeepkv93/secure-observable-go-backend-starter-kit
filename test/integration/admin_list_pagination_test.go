package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
)

type pageMeta struct {
	Page      int   `json:"page"`
	PageSize  int   `json:"page_size"`
	Total     int64 `json:"total"`
	TotalPage int   `json:"total_pages"`
}

type usersPageData struct {
	Items []struct {
		ID    uint   `json:"id"`
		Email string `json:"email"`
	} `json:"items"`
	Pagination pageMeta `json:"pagination"`
}

type rolesPageData struct {
	Items []struct {
		ID   uint   `json:"id"`
		Name string `json:"name"`
	} `json:"items"`
	Pagination pageMeta `json:"pagination"`
}

type permissionsPageData struct {
	Items []struct {
		ID       uint   `json:"id"`
		Resource string `json:"resource"`
		Action   string `json:"action"`
	} `json:"items"`
	Pagination pageMeta `json:"pagination"`
}

func TestAdminListUsersPaginationFilterSort(t *testing.T) {
	baseURL, adminClient, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.BootstrapAdminEmail = "admin-users-page@example.com"
		},
	})
	defer closeFn()

	registerAndLogin(t, adminClient, baseURL, "admin-users-page@example.com", "Valid#Pass1234")

	seedClient := newSessionClient(t)
	for i := 0; i < 4; i++ {
		registerOnly(t, seedClient, baseURL, fmt.Sprintf("page-user-%d@example.com", i))
	}

	resp, env := doJSON(t, adminClient, http.MethodGet, baseURL+"/api/v1/admin/users?page=1&page_size=2&sort_by=id&sort_order=asc", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("list users page1 failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	var p1 usersPageData
	if err := json.Unmarshal(env.Data, &p1); err != nil {
		t.Fatalf("decode users page1: %v", err)
	}
	if len(p1.Items) != 2 {
		t.Fatalf("expected 2 users in page1, got %d", len(p1.Items))
	}
	if p1.Pagination.Page != 1 || p1.Pagination.PageSize != 2 {
		t.Fatalf("unexpected pagination page1: %+v", p1.Pagination)
	}

	resp, env = doJSON(t, adminClient, http.MethodGet, baseURL+"/api/v1/admin/users?page=2&page_size=2&sort_by=id&sort_order=asc", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("list users page2 failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	var p2 usersPageData
	if err := json.Unmarshal(env.Data, &p2); err != nil {
		t.Fatalf("decode users page2: %v", err)
	}
	if len(p2.Items) != 2 {
		t.Fatalf("expected 2 users in page2, got %d", len(p2.Items))
	}
	if p1.Items[1].ID >= p2.Items[0].ID {
		t.Fatalf("expected deterministic asc ordering across pages, got page1_last=%d page2_first=%d", p1.Items[1].ID, p2.Items[0].ID)
	}

	resp, env = doJSON(t, adminClient, http.MethodGet, baseURL+"/api/v1/admin/users?email=page-user-1", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("filter users by email failed: status=%d", resp.StatusCode)
	}
	var filtered usersPageData
	if err := json.Unmarshal(env.Data, &filtered); err != nil {
		t.Fatalf("decode filtered users: %v", err)
	}
	if len(filtered.Items) == 0 {
		t.Fatal("expected at least one filtered user")
	}
	for _, item := range filtered.Items {
		if !strings.Contains(item.Email, "page-user-1") {
			t.Fatalf("unexpected email in filtered users: %s", item.Email)
		}
	}

	resp, env = doJSON(t, adminClient, http.MethodGet, baseURL+"/api/v1/admin/users?role=admin", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("filter users by role failed: status=%d", resp.StatusCode)
	}
	var adminOnly usersPageData
	if err := json.Unmarshal(env.Data, &adminOnly); err != nil {
		t.Fatalf("decode admin-role users: %v", err)
	}
	if len(adminOnly.Items) != 1 || adminOnly.Items[0].Email != "admin-users-page@example.com" {
		t.Fatalf("expected only bootstrap admin user in admin role filter, got %+v", adminOnly.Items)
	}

	resp, env = doJSON(t, adminClient, http.MethodGet, baseURL+"/api/v1/admin/users?page_size=101", nil, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized page_size, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "BAD_REQUEST" {
		t.Fatalf("expected BAD_REQUEST for oversized page_size, got %#v", env.Error)
	}
}

func TestAdminListRolesAndPermissionsPaginationFilterSort(t *testing.T) {
	baseURL, adminClient, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.BootstrapAdminEmail = "admin-rp-page@example.com"
		},
	})
	defer closeFn()

	registerAndLogin(t, adminClient, baseURL, "admin-rp-page@example.com", "Valid#Pass1234")

	for _, role := range []string{"qa-role-c", "qa-role-a", "qa-role-b"} {
		resp, env := doJSON(t, adminClient, http.MethodPost, baseURL+"/api/v1/admin/roles", map[string]any{
			"name":        role,
			"description": "qa role",
			"permissions": []string{"users:read"},
		}, nil)
		if resp.StatusCode != http.StatusCreated || !env.Success {
			t.Fatalf("create role %s failed: status=%d success=%v", role, resp.StatusCode, env.Success)
		}
	}
	resp, env := doJSON(t, adminClient, http.MethodGet, baseURL+"/api/v1/admin/roles?name=qa-role-&sort_by=name&sort_order=asc&page=1&page_size=2", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("list roles page1 failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	var rolesP1 rolesPageData
	if err := json.Unmarshal(env.Data, &rolesP1); err != nil {
		t.Fatalf("decode roles page1: %v", err)
	}
	if len(rolesP1.Items) != 2 {
		t.Fatalf("expected 2 roles on page1, got %d", len(rolesP1.Items))
	}
	if rolesP1.Items[0].Name != "qa-role-a" || rolesP1.Items[1].Name != "qa-role-b" {
		t.Fatalf("unexpected role ordering on page1: %+v", rolesP1.Items)
	}

	resp, env = doJSON(t, adminClient, http.MethodGet, baseURL+"/api/v1/admin/roles?name=qa-role-&sort_by=name&sort_order=asc&page=2&page_size=2", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("list roles page2 failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	var rolesP2 rolesPageData
	if err := json.Unmarshal(env.Data, &rolesP2); err != nil {
		t.Fatalf("decode roles page2: %v", err)
	}
	if len(rolesP2.Items) != 1 || rolesP2.Items[0].Name != "qa-role-c" {
		t.Fatalf("unexpected role ordering on page2: %+v", rolesP2.Items)
	}

	for _, action := range []string{"c", "a", "b"} {
		resp, env := doJSON(t, adminClient, http.MethodPost, baseURL+"/api/v1/admin/permissions", map[string]string{
			"resource": "qa_resource",
			"action":   "act_" + action,
		}, nil)
		if resp.StatusCode != http.StatusCreated || !env.Success {
			t.Fatalf("create permission %s failed: status=%d success=%v", action, resp.StatusCode, env.Success)
		}
	}
	resp, env = doJSON(t, adminClient, http.MethodGet, baseURL+"/api/v1/admin/permissions?resource=qa_resource&sort_by=action&sort_order=asc&page=1&page_size=2", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("list permissions page1 failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	var permsP1 permissionsPageData
	if err := json.Unmarshal(env.Data, &permsP1); err != nil {
		t.Fatalf("decode permissions page1: %v", err)
	}
	if len(permsP1.Items) != 2 {
		t.Fatalf("expected 2 permissions page1, got %d", len(permsP1.Items))
	}
	if permsP1.Items[0].Action != "act_a" || permsP1.Items[1].Action != "act_b" {
		t.Fatalf("unexpected permission ordering on page1: %+v", permsP1.Items)
	}
	resp, env = doJSON(t, adminClient, http.MethodGet, baseURL+"/api/v1/admin/permissions?resource=qa_resource&sort_by=action&sort_order=asc&page=2&page_size=2", nil, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("list permissions page2 failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	var permsP2 permissionsPageData
	if err := json.Unmarshal(env.Data, &permsP2); err != nil {
		t.Fatalf("decode permissions page2: %v", err)
	}
	if len(permsP2.Items) != 1 || permsP2.Items[0].Action != "act_c" {
		t.Fatalf("unexpected permission ordering on page2: %+v", permsP2.Items)
	}
}

func TestAdminListInvalidSortByRejected(t *testing.T) {
	baseURL, adminClient, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.BootstrapAdminEmail = "admin-invalid-sort@example.com"
		},
	})
	defer closeFn()

	registerAndLogin(t, adminClient, baseURL, "admin-invalid-sort@example.com", "Valid#Pass1234")

	for _, path := range []string{
		"/api/v1/admin/users?sort_by=bogus",
		"/api/v1/admin/roles?sort_by=bogus",
		"/api/v1/admin/permissions?sort_by=bogus",
	} {
		resp, env := doJSON(t, adminClient, http.MethodGet, baseURL+path, nil, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d", path, resp.StatusCode)
		}
		if env.Error == nil || env.Error.Code != "BAD_REQUEST" {
			t.Fatalf("expected BAD_REQUEST for %s, got %#v", path, env.Error)
		}
	}
}

func registerOnly(t *testing.T, client *http.Client, baseURL, email string) {
	t.Helper()
	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/register", map[string]string{
		"email":    email,
		"name":     "Pagination User",
		"password": "Valid#Pass1234",
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("register user %s failed: status=%d success=%v", email, resp.StatusCode, env.Success)
	}
}

func newSessionClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}
	return &http.Client{Jar: jar}
}
