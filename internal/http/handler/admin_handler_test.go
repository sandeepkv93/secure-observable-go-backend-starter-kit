package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
	repogomock "github.com/sandeepkv93/everything-backend-starter-kit/internal/repository/gomock"
	servicegomock "github.com/sandeepkv93/everything-backend-starter-kit/internal/service/gomock"
	"go.uber.org/mock/gomock"
	"gorm.io/gorm"
)

type nopTB struct{}

func (nopTB) Errorf(string, ...any) {}
func (nopTB) Fatalf(string, ...any) {}
func (nopTB) Helper()               {}

type adminUserState struct {
	setRolesFn func(userID uint, roleIDs []uint) error
	getByIDFn  func(id uint) (*domain.User, []string, error)
}

func (s *adminUserState) GetByID(id uint) (*domain.User, []string, error) {
	if s.getByIDFn != nil {
		return s.getByIDFn(id)
	}
	return &domain.User{ID: id}, nil, nil
}

func (s *adminUserState) SetRoles(userID uint, roleIDs []uint) error {
	if s.setRolesFn != nil {
		return s.setRolesFn(userID, roleIDs)
	}
	return nil
}

type permissionResolverState struct {
	invalidateUserCalls []uint
	invalidateAllCount  int
}

func (s *permissionResolverState) InvalidateUser(ctx context.Context, userID uint) error {
	s.invalidateUserCalls = append(s.invalidateUserCalls, userID)
	return nil
}

func (s *permissionResolverState) InvalidateAll(ctx context.Context) error {
	s.invalidateAllCount++
	return nil
}

type adminListCacheState struct {
	invalidate map[string]int
}

func (s *adminListCacheState) InvalidateNamespace(ctx context.Context, namespace string) error {
	if s.invalidate == nil {
		s.invalidate = map[string]int{}
	}
	s.invalidate[namespace]++
	return nil
}

type negativeLookupState struct {
	hits       map[string]bool
	invalidate map[string]int
}

func (s *negativeLookupState) Get(ctx context.Context, namespace, key string) (bool, error) {
	if s.hits == nil {
		return false, nil
	}
	return s.hits[namespace+"|"+key], nil
}

func (s *negativeLookupState) InvalidateNamespace(ctx context.Context, namespace string) error {
	if s.invalidate == nil {
		s.invalidate = map[string]int{}
	}
	s.invalidate[namespace]++
	return nil
}

type adminRoleRepoState struct {
	rolesByID   map[uint]*domain.Role
	rolesByName map[string]*domain.Role
	findByIDN   int
	createFn    func(role *domain.Role, permissionIDs []uint) error
	updateFn    func(role *domain.Role, permissionIDs []uint) error
	deleteFn    func(id uint) error
}

func (s *adminRoleRepoState) FindByID(id uint) (*domain.Role, error) {
	s.findByIDN++
	if role, ok := s.rolesByID[id]; ok {
		cp := *role
		return &cp, nil
	}
	return nil, repository.ErrRoleNotFound
}

func (s *adminRoleRepoState) FindByName(name string) (*domain.Role, error) {
	if s.rolesByName != nil {
		if role, ok := s.rolesByName[name]; ok {
			cp := *role
			return &cp, nil
		}
	}
	return nil, repository.ErrRoleNotFound
}

func (s *adminRoleRepoState) Create(role *domain.Role, permissionIDs []uint) error {
	if s.createFn != nil {
		return s.createFn(role, permissionIDs)
	}
	if role.ID == 0 {
		role.ID = 501
	}
	if s.rolesByID == nil {
		s.rolesByID = map[uint]*domain.Role{}
	}
	s.rolesByID[role.ID] = &domain.Role{ID: role.ID, Name: role.Name, Description: role.Description}
	return nil
}

func (s *adminRoleRepoState) Update(role *domain.Role, permissionIDs []uint) error {
	if s.updateFn != nil {
		return s.updateFn(role, permissionIDs)
	}
	if s.rolesByID == nil {
		s.rolesByID = map[uint]*domain.Role{}
	}
	existing, ok := s.rolesByID[role.ID]
	if !ok {
		return repository.ErrRoleNotFound
	}
	existing.Name = role.Name
	existing.Description = role.Description
	return nil
}

func (s *adminRoleRepoState) DeleteByID(id uint) error {
	if s.deleteFn != nil {
		return s.deleteFn(id)
	}
	if s.rolesByID != nil {
		delete(s.rolesByID, id)
	}
	return nil
}

type adminPermRepoState struct {
	byID      map[uint]*domain.Permission
	findPairs func(pairs [][2]string) ([]domain.Permission, error)
	updateFn  func(permission *domain.Permission) error
	deleteFn  func(id uint) error
}

func (s *adminPermRepoState) FindByID(id uint) (*domain.Permission, error) {
	if p, ok := s.byID[id]; ok {
		cp := *p
		return &cp, nil
	}
	return nil, repository.ErrPermissionNotFound
}

func (s *adminPermRepoState) FindByPairs(pairs [][2]string) ([]domain.Permission, error) {
	if s.findPairs != nil {
		return s.findPairs(pairs)
	}
	out := make([]domain.Permission, 0, len(pairs))
	nextID := uint(1)
	for _, pair := range pairs {
		out = append(out, domain.Permission{ID: nextID, Resource: pair[0], Action: pair[1]})
		nextID++
	}
	return out, nil
}

func (s *adminPermRepoState) FindByResourceAction(resource, action string) (*domain.Permission, error) {
	for _, p := range s.byID {
		if p.Resource == resource && p.Action == action {
			cp := *p
			return &cp, nil
		}
	}
	return nil, repository.ErrPermissionNotFound
}

func (s *adminPermRepoState) Create(permission *domain.Permission) error {
	if permission.ID == 0 {
		permission.ID = 700
	}
	if s.byID == nil {
		s.byID = map[uint]*domain.Permission{}
	}
	s.byID[permission.ID] = &domain.Permission{ID: permission.ID, Resource: permission.Resource, Action: permission.Action}
	return nil
}

func (s *adminPermRepoState) Update(permission *domain.Permission) error {
	if s.updateFn != nil {
		return s.updateFn(permission)
	}
	if _, ok := s.byID[permission.ID]; !ok {
		return repository.ErrPermissionNotFound
	}
	s.byID[permission.ID] = &domain.Permission{ID: permission.ID, Resource: permission.Resource, Action: permission.Action}
	return nil
}

func (s *adminPermRepoState) DeleteByID(id uint) error {
	if s.deleteFn != nil {
		return s.deleteFn(id)
	}
	delete(s.byID, id)
	return nil
}

func newAdminHandlerFixture() (*AdminHandler, *permissionResolverState, *adminListCacheState, *negativeLookupState, *adminRoleRepoState, *adminPermRepoState, *adminUserState) {
	ctrl := gomock.NewController(nopTB{})
	resolver := &permissionResolverState{}
	adminCache := &adminListCacheState{invalidate: map[string]int{}}
	neg := &negativeLookupState{hits: map[string]bool{}, invalidate: map[string]int{}}
	roleRepo := &adminRoleRepoState{rolesByID: map[uint]*domain.Role{}, rolesByName: map[string]*domain.Role{}}
	permRepo := &adminPermRepoState{byID: map[uint]*domain.Permission{}}
	userSvc := &adminUserState{}
	userSvc.getByIDFn = func(id uint) (*domain.User, []string, error) {
		return &domain.User{
			ID: id,
			Roles: []domain.Role{
				{ID: 100, Name: "admin", Permissions: []domain.Permission{{Resource: "roles", Action: "write"}, {Resource: "permissions", Action: "write"}}},
				{ID: 101, Name: "backup", Permissions: []domain.Permission{{Resource: "roles", Action: "write"}}},
			},
		}, []string{"roles:write", "permissions:write"}, nil
	}

	cfg := &config.Config{
		AdminListCacheTTL:        time.Minute,
		NegativeLookupCacheTTL:   time.Minute,
		RBACProtectedRoles:       []string{"admin", "user"},
		RBACProtectedPermissions: []string{"users:read", "users:write", "roles:read", "roles:write", "permissions:read", "permissions:write"},
	}

	userSvcMock := servicegomock.NewMockUserServiceInterface(ctrl)
	userRepoMock := repogomock.NewMockUserRepository(ctrl)
	roleRepoMock := repogomock.NewMockRoleRepository(ctrl)
	permRepoMock := repogomock.NewMockPermissionRepository(ctrl)
	rbacMock := servicegomock.NewMockRBACAuthorizer(ctrl)
	resolverMock := servicegomock.NewMockPermissionResolver(ctrl)
	adminCacheMock := servicegomock.NewMockAdminListCacheStore(ctrl)
	negMock := servicegomock.NewMockNegativeLookupCacheStore(ctrl)

	userSvcMock.EXPECT().GetByID(gomock.Any()).AnyTimes().DoAndReturn(userSvc.GetByID)
	userSvcMock.EXPECT().List().AnyTimes().Return([]domain.User{}, nil)
	userSvcMock.EXPECT().SetRoles(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(userSvc.SetRoles)

	userRepoMock.EXPECT().FindByID(gomock.Any()).AnyTimes().Return(nil, gorm.ErrRecordNotFound)
	userRepoMock.EXPECT().FindByEmail(gomock.Any()).AnyTimes().Return(nil, gorm.ErrRecordNotFound)
	userRepoMock.EXPECT().Create(gomock.Any()).AnyTimes().Return(nil)
	userRepoMock.EXPECT().Update(gomock.Any()).AnyTimes().Return(nil)
	userRepoMock.EXPECT().List().AnyTimes().Return([]domain.User{}, nil)
	userRepoMock.EXPECT().ListPaged(gomock.Any()).AnyTimes().Return(repository.PageResult[domain.User]{}, nil)
	userRepoMock.EXPECT().SetRoles(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	userRepoMock.EXPECT().AddRole(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)

	roleRepoMock.EXPECT().FindByID(gomock.Any()).AnyTimes().DoAndReturn(roleRepo.FindByID)
	roleRepoMock.EXPECT().FindByName(gomock.Any()).AnyTimes().DoAndReturn(roleRepo.FindByName)
	roleRepoMock.EXPECT().List().AnyTimes().Return([]domain.Role{}, nil)
	roleRepoMock.EXPECT().ListPaged(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(repository.PageResult[domain.Role]{}, nil)
	roleRepoMock.EXPECT().Create(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(roleRepo.Create)
	roleRepoMock.EXPECT().Update(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(roleRepo.Update)
	roleRepoMock.EXPECT().DeleteByID(gomock.Any()).AnyTimes().DoAndReturn(roleRepo.DeleteByID)

	permRepoMock.EXPECT().List().AnyTimes().Return([]domain.Permission{}, nil)
	permRepoMock.EXPECT().ListPaged(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(repository.PageResult[domain.Permission]{}, nil)
	permRepoMock.EXPECT().FindByID(gomock.Any()).AnyTimes().DoAndReturn(permRepo.FindByID)
	permRepoMock.EXPECT().FindByPairs(gomock.Any()).AnyTimes().DoAndReturn(permRepo.FindByPairs)
	permRepoMock.EXPECT().FindByResourceAction(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(permRepo.FindByResourceAction)
	permRepoMock.EXPECT().Create(gomock.Any()).AnyTimes().DoAndReturn(permRepo.Create)
	permRepoMock.EXPECT().Update(gomock.Any()).AnyTimes().DoAndReturn(permRepo.Update)
	permRepoMock.EXPECT().DeleteByID(gomock.Any()).AnyTimes().DoAndReturn(permRepo.DeleteByID)

	rbacMock.EXPECT().HasPermission(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(func(perms []string, required string) bool {
		for _, p := range perms {
			if p == required {
				return true
			}
		}
		return false
	})
	resolverMock.EXPECT().ResolvePermissions(gomock.Any(), gomock.Any()).AnyTimes().Return([]string{}, nil)
	resolverMock.EXPECT().InvalidateUser(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(resolver.InvalidateUser)
	resolverMock.EXPECT().InvalidateAll(gomock.Any()).AnyTimes().DoAndReturn(resolver.InvalidateAll)
	adminCacheMock.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil, false, nil)
	adminCacheMock.EXPECT().Set(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	adminCacheMock.EXPECT().InvalidateNamespace(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(adminCache.InvalidateNamespace)
	negMock.EXPECT().Get(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(neg.Get)
	negMock.EXPECT().Set(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	negMock.EXPECT().InvalidateNamespace(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(neg.InvalidateNamespace)

	h := NewAdminHandler(
		userSvcMock,
		userRepoMock,
		roleRepoMock,
		permRepoMock,
		rbacMock,
		resolverMock,
		adminCacheMock,
		negMock,
		nil,
		cfg,
	)
	return h, resolver, adminCache, neg, roleRepo, permRepo, userSvc
}

func TestAdminHandlerConditionalETag304(t *testing.T) {
	h, _, _, _, _, _, _ := newAdminHandlerFixture()
	payload := map[string]any{"items": []string{"a", "b"}, "pagination": map[string]any{"page": 1}}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	etag := buildStrongETag(encoded)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/roles", nil)
	req.Header.Set("If-None-Match", etag)
	rr := httptest.NewRecorder()
	status := h.respondAdminListWithConditionalETag(rr, req, "admin.roles.list", payload, nil)

	if status != "not_modified" {
		t.Fatalf("expected status not_modified, got %q", status)
	}
	if rr.Code != http.StatusNotModified {
		t.Fatalf("expected 304, got %d", rr.Code)
	}
	if got := rr.Header().Get("ETag"); got != etag {
		t.Fatalf("expected ETag %q, got %q", etag, got)
	}
}

func TestAdminHandlerNegativeLookupStaleFalsePositiveRoleUpdate(t *testing.T) {
	h, _, _, neg, roleRepo, _, _ := newAdminHandlerFixture()
	roleRepo.rolesByID[5] = &domain.Role{ID: 5, Name: "admin"}
	neg.hits[roleNegativeLookupNamespace+"|5"] = true

	req := withURLParam(httptest.NewRequest(http.MethodPatch, "/api/v1/admin/roles/5", strings.NewReader(`{"name":"admin2","permissions":["roles:write"]}`)), "id", "5")
	rr := httptest.NewRecorder()
	h.UpdateRole(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 protected role on stale false positive path, got %d", rr.Code)
	}
	if roleRepo.findByIDN == 0 {
		t.Fatal("expected roleRepo.FindByID to be called despite negative cache hit")
	}
}

func TestAdminHandlerMutationCacheInvalidation(t *testing.T) {
	h, resolver, adminCache, neg, roleRepo, permRepo, userSvc := newAdminHandlerFixture()

	t.Run("set user roles invalidates user cache and user permission cache", func(t *testing.T) {
		userSvc.setRolesFn = func(userID uint, roleIDs []uint) error { return nil }
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/api/v1/admin/users/10/roles", strings.NewReader(`{"role_ids":[1,2]}`)), "id", "10")
		rr := httptest.NewRecorder()
		h.SetUserRoles(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if adminCache.invalidate["admin.users.list"] == 0 {
			t.Fatal("expected admin.users.list invalidation")
		}
		if len(resolver.invalidateUserCalls) == 0 || resolver.invalidateUserCalls[len(resolver.invalidateUserCalls)-1] != 10 {
			t.Fatalf("expected permission cache invalidation for user 10, got %+v", resolver.invalidateUserCalls)
		}
	})

	t.Run("create role invalidates role and user list caches + negative lookup", func(t *testing.T) {
		permRepo.findPairs = func(pairs [][2]string) ([]domain.Permission, error) {
			return []domain.Permission{{ID: 1, Resource: "roles", Action: "write"}}, nil
		}
		roleRepo.createFn = func(role *domain.Role, permissionIDs []uint) error {
			role.ID = 99
			roleRepo.rolesByID[99] = &domain.Role{ID: 99, Name: role.Name}
			return nil
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/roles", strings.NewReader(`{"name":"auditor","description":"x","permissions":["roles:write"]}`))
		req = withClaims(req, "42")
		rr := httptest.NewRecorder()
		h.CreateRole(rr, req)
		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d", rr.Code)
		}
		if adminCache.invalidate["admin.roles.list"] == 0 || adminCache.invalidate["admin.users.list"] == 0 {
			t.Fatalf("expected role/user list invalidations, got %+v", adminCache.invalidate)
		}
		if neg.invalidate[roleNegativeLookupNamespace] == 0 {
			t.Fatalf("expected role negative lookup invalidation, got %+v", neg.invalidate)
		}
		if resolver.invalidateAllCount == 0 {
			t.Fatal("expected permission cache invalidate all")
		}
	})

	t.Run("update permission invalidates permission and role list caches + negative lookup", func(t *testing.T) {
		permRepo.byID[7] = &domain.Permission{ID: 7, Resource: "reports", Action: "read"}
		permRepo.updateFn = func(permission *domain.Permission) error {
			permRepo.byID[permission.ID] = &domain.Permission{ID: permission.ID, Resource: permission.Resource, Action: permission.Action}
			return nil
		}
		req := withURLParam(httptest.NewRequest(http.MethodPatch, "/api/v1/admin/permissions/7", strings.NewReader(`{"resource":"reports","action":"write"}`)), "id", "7")
		req = withClaims(req, "42")
		rr := httptest.NewRecorder()
		h.UpdatePermission(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if adminCache.invalidate["admin.permissions.list"] == 0 || adminCache.invalidate["admin.roles.list"] == 0 {
			t.Fatalf("expected permission/role list invalidations, got %+v", adminCache.invalidate)
		}
		if neg.invalidate[permissionNegativeLookupNamespace] == 0 {
			t.Fatalf("expected permission negative lookup invalidation, got %+v", neg.invalidate)
		}
	})

	t.Run("delete permission invalidates permission and role list caches + negative lookup", func(t *testing.T) {
		permRepo.byID[8] = &domain.Permission{ID: 8, Resource: "reports", Action: "read"}
		permRepo.deleteFn = func(id uint) error {
			delete(permRepo.byID, id)
			return nil
		}
		req := withURLParam(httptest.NewRequest(http.MethodDelete, "/api/v1/admin/permissions/8", nil), "id", "8")
		req = withClaims(req, "42")
		rr := httptest.NewRecorder()
		h.DeletePermission(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if adminCache.invalidate["admin.permissions.list"] == 0 || adminCache.invalidate["admin.roles.list"] == 0 {
			t.Fatalf("expected permission/role list invalidations, got %+v", adminCache.invalidate)
		}
		if neg.invalidate[permissionNegativeLookupNamespace] == 0 {
			t.Fatalf("expected permission negative lookup invalidation, got %+v", neg.invalidate)
		}
	})
}

func TestAdminHandlerLockoutHelpersAndListParserFailures(t *testing.T) {
	h, _, _, _, _, _, _ := newAdminHandlerFixture()

	t.Run("wouldLockOutRoleMutation true/false", func(t *testing.T) {
		singleRoleHandler, _, _, _, _, _, singleRoleSvc := newAdminHandlerFixture()
		singleRoleSvc.getByIDFn = func(id uint) (*domain.User, []string, error) {
			return &domain.User{
				ID: id,
				Roles: []domain.Role{
					{ID: 100, Name: "admin", Permissions: []domain.Permission{{Resource: "roles", Action: "write"}}},
				},
			}, []string{"roles:write"}, nil
		}
		if !singleRoleHandler.wouldLockOutRoleMutation(42, 100, "roles:write", []string{"users:read"}) {
			t.Fatal("expected lockout when required permission removed")
		}
		if h.wouldLockOutRoleMutation(42, 100, "roles:write", []string{"users:read"}) {
			t.Fatal("did not expect lockout when another actor role still grants required permission")
		}
		if h.wouldLockOutRoleMutation(42, 100, "roles:write", []string{"roles:write"}) {
			t.Fatal("did not expect lockout when required permission retained")
		}
	})

	t.Run("wouldLockOutPermissionMutation and deletion", func(t *testing.T) {
		if !h.wouldLockOutPermissionMutation(42, "roles:write", "users:write", "roles:write") {
			t.Fatal("expected lockout when renaming away required permission")
		}
		if h.wouldLockOutPermissionMutation(42, "users:read", "users:write", "permissions:write") {
			t.Fatal("did not expect lockout when required permission unaffected")
		}
		if !h.wouldLockOutPermissionDeletion(42, "permissions:write", "permissions:write") {
			t.Fatal("expected lockout when deleting required permission")
		}
	})

	t.Run("list endpoint parser failures", func(t *testing.T) {
		cases := []struct {
			name string
			fn   func(w http.ResponseWriter, r *http.Request)
			url  string
		}{
			{name: "list users invalid page", fn: h.ListUsers, url: "/api/v1/admin/users?page=0"},
			{name: "list roles invalid sort_order", fn: h.ListRoles, url: "/api/v1/admin/roles?sort_order=up"},
			{name: "list permissions invalid sort_by", fn: h.ListPermissions, url: "/api/v1/admin/permissions?sort_by=nope"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rr := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, tc.url, nil)
				tc.fn(rr, req)
				if rr.Code != http.StatusBadRequest {
					t.Fatalf("expected 400, got %d", rr.Code)
				}
			})
		}
	})
}

func TestParsePathIDStrict(t *testing.T) {
	t.Run("accepts numeric id", func(t *testing.T) {
		id, err := parsePathID("42")
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if id != 42 {
			t.Fatalf("expected id 42, got %d", id)
		}
	})

	t.Run("rejects trailing characters", func(t *testing.T) {
		if _, err := parsePathID("12abc"); err == nil {
			t.Fatal("expected error for trailing characters")
		}
	})
}

func FuzzParseAdminListPageRequestRobustness(f *testing.F) {
	f.Add("", "")
	f.Add("1", "20")
	f.Add("0", "0")
	f.Add("-10", "-5")
	f.Add("999999999", "101")
	f.Add("🔥", "∞")

	f.Fuzz(func(t *testing.T, rawPage, rawPageSize string) {
		if len(rawPage) > 256 {
			rawPage = rawPage[:256]
		}
		if len(rawPageSize) > 256 {
			rawPageSize = rawPageSize[:256]
		}

		q := url.Values{}
		q.Set("page", rawPage)
		q.Set("page_size", rawPageSize)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users?"+q.Encode(), nil)
		got, err := parsePageRequest(req)
		if err == nil {
			if got.Page < 1 {
				t.Fatalf("page must be >= 1, got %d", got.Page)
			}
			if got.PageSize < 1 || got.PageSize > repository.MaxPageSize {
				t.Fatalf("page_size out of bounds: %d", got.PageSize)
			}
			again, errAgain := parsePageRequest(req)
			if errAgain != nil {
				t.Fatalf("unexpected non-deterministic error on same input: %v", errAgain)
			}
			if got != again {
				t.Fatalf("parsePageRequest must be deterministic: first=%+v second=%+v", got, again)
			}
			return
		}

		if got != (repository.PageRequest{}) {
			t.Fatalf("expected zero-value PageRequest on error, got %+v", got)
		}
	})
}

func FuzzParseAdminListSortParamsRobustness(f *testing.F) {
	f.Add("", "", "created_at")
	f.Add("email", "asc", "created_at")
	f.Add("name", "desc", "created_at")
	f.Add("nope", "up", "created_at")
	f.Add("🔥", "∞", "created_at")

	allowed := map[string]struct{}{
		"id":         {},
		"created_at": {},
		"updated_at": {},
		"email":      {},
		"name":       {},
		"status":     {},
	}

	f.Fuzz(func(t *testing.T, rawSortBy, rawSortOrder, defaultField string) {
		if len(rawSortBy) > 256 {
			rawSortBy = rawSortBy[:256]
		}
		if len(rawSortOrder) > 256 {
			rawSortOrder = rawSortOrder[:256]
		}
		defaultField = strings.ToLower(strings.TrimSpace(defaultField))
		if _, ok := allowed[defaultField]; !ok {
			defaultField = "created_at"
		}

		q := url.Values{}
		q.Set("sort_by", rawSortBy)
		q.Set("sort_order", rawSortOrder)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users?"+q.Encode(), nil)
		sortBy, sortOrder, err := parseSortParams(req, defaultField, allowed)
		if err == nil {
			if _, ok := allowed[sortBy]; !ok {
				t.Fatalf("sort_by must be in allowlist, got %q", sortBy)
			}
			if sortOrder != "asc" && sortOrder != "desc" {
				t.Fatalf("sort_order must be asc or desc, got %q", sortOrder)
			}
			againBy, againOrder, errAgain := parseSortParams(req, defaultField, allowed)
			if errAgain != nil {
				t.Fatalf("unexpected non-deterministic error on same input: %v", errAgain)
			}
			if sortBy != againBy || sortOrder != againOrder {
				t.Fatalf("parseSortParams must be deterministic: first=(%s,%s) second=(%s,%s)", sortBy, sortOrder, againBy, againOrder)
			}
			return
		}

		if sortBy != "" || sortOrder != "" {
			t.Fatalf("expected empty outputs on error, got sortBy=%q sortOrder=%q", sortBy, sortOrder)
		}
	})
}
