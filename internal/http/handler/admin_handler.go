package handler

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/sync/singleflight"
	"gorm.io/gorm"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/database"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/response"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/service"
)

var permissionPartRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

const (
	roleNegativeLookupNamespace       = "admin.role.not_found"
	permissionNegativeLookupNamespace = "admin.permission.not_found"
)

type AdminHandler struct {
	userSvc              service.UserServiceInterface
	userRepo             repository.UserRepository
	roleRepo             repository.RoleRepository
	permRepo             repository.PermissionRepository
	rbac                 service.RBACAuthorizer
	permissionResolver   service.PermissionResolver
	adminListCache       service.AdminListCacheStore
	negativeLookupCache  service.NegativeLookupCacheStore
	adminListSingleGroup singleflight.Group
	adminListCacheTTL    time.Duration
	negativeLookupTTL    time.Duration
	db                   *gorm.DB
	cfg                  *config.Config
	protectedRoles       map[string]struct{}
	protectedPermissions map[string]struct{}
}

func NewAdminHandler(
	userSvc service.UserServiceInterface,
	userRepo repository.UserRepository,
	roleRepo repository.RoleRepository,
	permRepo repository.PermissionRepository,
	rbac service.RBACAuthorizer,
	permissionResolver service.PermissionResolver,
	adminListCache service.AdminListCacheStore,
	negativeLookupCache service.NegativeLookupCacheStore,
	db *gorm.DB,
	cfg *config.Config,
) *AdminHandler {
	protectedRoles := make(map[string]struct{}, len(cfg.RBACProtectedRoles))
	for _, role := range cfg.RBACProtectedRoles {
		trimmed := strings.ToLower(strings.TrimSpace(role))
		if trimmed != "" {
			protectedRoles[trimmed] = struct{}{}
		}
	}
	protectedPerms := make(map[string]struct{}, len(cfg.RBACProtectedPermissions))
	for _, perm := range cfg.RBACProtectedPermissions {
		trimmed := strings.ToLower(strings.TrimSpace(perm))
		if trimmed != "" {
			protectedPerms[trimmed] = struct{}{}
		}
	}
	return &AdminHandler{
		userSvc:              userSvc,
		userRepo:             userRepo,
		roleRepo:             roleRepo,
		permRepo:             permRepo,
		rbac:                 rbac,
		permissionResolver:   permissionResolver,
		adminListCache:       adminListCache,
		negativeLookupCache:  negativeLookupCache,
		adminListCacheTTL:    cfg.AdminListCacheTTL,
		negativeLookupTTL:    cfg.NegativeLookupCacheTTL,
		db:                   db,
		cfg:                  cfg,
		protectedRoles:       protectedRoles,
		protectedPermissions: protectedPerms,
	}
}

func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAdminListRequestDuration(r.Context(), "admin.users", status, time.Since(start))
	}()

	cacheNamespace := "admin.users.list"
	cacheKey := h.adminListCacheKey(r, cacheNamespace)
	if cachedData, ok := h.readAdminListCache(r, cacheNamespace, cacheKey); ok {
		response.JSON(w, r, http.StatusOK, cachedData)
		return
	}

	pageReq, err := parsePageRequest(r)
	if err != nil {
		status = "bad_request"
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}
	observability.RecordAdminListPageSize(r.Context(), "admin.users", pageReq.PageSize)
	sortBy, sortOrder, err := parseSortParams(r, "created_at", map[string]struct{}{
		"id":            {},
		"created_at":    {},
		"updated_at":    {},
		"email":         {},
		"name":          {},
		"status":        {},
		"last_login_at": {},
	})
	if err != nil {
		status = "bad_request"
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}

	filterEmail := strings.TrimSpace(r.URL.Query().Get("email"))
	filterStatus := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	filterRole := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("role")))
	sfKey := cacheNamespace + "|" + cacheKey
	result, err, shared := h.adminListSingleGroup.Do(sfKey, func() (interface{}, error) {
		usersPage, err := h.userRepo.ListPaged(repository.UserListQuery{
			PageRequest: pageReq,
			SortBy:      sortBy,
			SortOrder:   sortOrder,
			Email:       filterEmail,
			Status:      filterStatus,
			Role:        filterRole,
		})
		if err != nil {
			return nil, err
		}
		payload := paginatedData(usersPage.Items, usersPage.Page, usersPage.PageSize, usersPage.Total, usersPage.TotalPages)
		h.writeAdminListCache(r, cacheNamespace, cacheKey, payload)
		return payload, nil
	})
	if shared {
		observability.RecordAdminListCacheEvent(r.Context(), cacheNamespace, "singleflight_shared")
	} else {
		observability.RecordAdminListCacheEvent(r.Context(), cacheNamespace, "singleflight_leader")
	}
	if err != nil {
		observability.RecordAdminListCacheEvent(r.Context(), cacheNamespace, "error")
		status = "error"
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to list users", nil)
		return
	}
	payload, ok := result.(map[string]any)
	if !ok {
		status = "error"
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to encode response", nil)
		return
	}
	response.JSON(w, r, http.StatusOK, payload)
}

func (h *AdminHandler) SetUserRoles(w http.ResponseWriter, r *http.Request) {
	idParam := chi.URLParam(r, "id")
	userID, err := parsePathID(idParam)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid user id", nil)
		return
	}
	var body struct {
		RoleIDs []uint `json:"role_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	if err := h.userSvc.SetRoles(userID, body.RoleIDs); err != nil {
		observability.RecordAdminRBACMutation(r.Context(), "user_role", "set_user_roles", "error")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to set roles", nil)
		return
	}
	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "admin.user_roles.update",
		ActorUserID: adminActorID(r),
		TargetType:  "user",
		TargetID:    strconv.FormatUint(uint64(userID), 10),
		Action:      "set_roles",
		Outcome:     "success",
		Reason:      "roles_updated",
	}, "role_ids", body.RoleIDs)
	observability.RecordAdminRBACMutation(r.Context(), "user_role", "set_user_roles", "success")
	h.invalidateRBACPermissionCacheUser(r, userID)
	h.invalidateAdminListCaches(r, "admin.users.list")
	response.JSON(w, r, http.StatusOK, map[string]any{"user_id": userID, "role_ids": body.RoleIDs})
}

func (h *AdminHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAdminListRequestDuration(r.Context(), "admin.roles", status, time.Since(start))
	}()

	cacheNamespace := "admin.roles.list"
	cacheKey := h.adminListCacheKey(r, cacheNamespace)
	if cachedData, ok := h.readAdminListCache(r, cacheNamespace, cacheKey); ok {
		status = h.respondAdminListWithConditionalETag(w, r, cacheNamespace, nil, cachedData)
		return
	}

	pageReq, err := parsePageRequest(r)
	if err != nil {
		status = "bad_request"
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}
	observability.RecordAdminListPageSize(r.Context(), "admin.roles", pageReq.PageSize)
	sortBy, sortOrder, err := parseSortParams(r, "created_at", map[string]struct{}{
		"id":         {},
		"created_at": {},
		"updated_at": {},
		"name":       {},
	})
	if err != nil {
		status = "bad_request"
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}
	filterName := strings.TrimSpace(r.URL.Query().Get("name"))
	sfKey := cacheNamespace + "|" + cacheKey
	result, err, shared := h.adminListSingleGroup.Do(sfKey, func() (interface{}, error) {
		rolesPage, err := h.roleRepo.ListPaged(pageReq, sortBy, sortOrder, filterName)
		if err != nil {
			return nil, err
		}
		payload := paginatedData(rolesPage.Items, rolesPage.Page, rolesPage.PageSize, rolesPage.Total, rolesPage.TotalPages)
		h.writeAdminListCache(r, cacheNamespace, cacheKey, payload)
		return payload, nil
	})
	if shared {
		observability.RecordAdminListCacheEvent(r.Context(), cacheNamespace, "singleflight_shared")
	} else {
		observability.RecordAdminListCacheEvent(r.Context(), cacheNamespace, "singleflight_leader")
	}
	if err != nil {
		observability.RecordAdminListCacheEvent(r.Context(), cacheNamespace, "error")
		status = "error"
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to list roles", nil)
		return
	}
	payload, ok := result.(map[string]any)
	if !ok {
		status = "error"
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to encode response", nil)
		return
	}
	status = h.respondAdminListWithConditionalETag(w, r, cacheNamespace, payload, nil)
}

func (h *AdminHandler) CreateRole(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	pairs, err := parsePermissionPairs(body.Permissions)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}
	perms, err := h.permRepo.FindByPairs(pairs)
	if err != nil {
		observability.RecordAdminRBACMutation(r.Context(), "role", "create", "error")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load permissions", nil)
		return
	}
	if len(perms) != len(pairs) {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "one or more permissions do not exist", nil)
		return
	}
	permIDs := make([]uint, 0, len(perms))
	for _, p := range perms {
		permIDs = append(permIDs, p.ID)
	}
	role := &domain.Role{Name: strings.TrimSpace(body.Name), Description: strings.TrimSpace(body.Description)}
	if err := h.roleRepo.Create(role, permIDs); err != nil {
		if isConflictError(err) {
			observability.RecordAdminRBACMutation(r.Context(), "role", "create", "rejected")
			response.Error(w, r, http.StatusConflict, "CONFLICT", "role already exists", nil)
			return
		}
		observability.RecordAdminRBACMutation(r.Context(), "role", "create", "error")
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "failed to create role", nil)
		return
	}
	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "admin.role.create",
		ActorUserID: adminActorID(r),
		TargetType:  "role",
		TargetID:    strconv.FormatUint(uint64(role.ID), 10),
		Action:      "create",
		Outcome:     "success",
		Reason:      "role_created",
	}, "role_name", role.Name, "after_permissions", body.Permissions)
	observability.RecordAdminRBACMutation(r.Context(), "role", "create", "success")
	h.invalidateRBACPermissionCacheAll(r)
	h.invalidateAdminListCaches(r, "admin.roles.list", "admin.users.list")
	h.invalidateNegativeLookupCaches(r, roleNegativeLookupNamespace)
	response.JSON(w, r, http.StatusCreated, role)
}

func (h *AdminHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := parsePathID(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid role id", nil)
		return
	}
	roleCacheKey := strconv.FormatUint(uint64(roleID), 10)
	var before *domain.Role
	if h.readNegativeLookupCache(r, roleNegativeLookupNamespace, roleCacheKey) {
		cachedRole, findErr := h.roleRepo.FindByID(roleID)
		if findErr != nil {
			if errors.Is(findErr, repository.ErrRoleNotFound) {
				observability.RecordAdminNegativeLookupEffectiveness(r.Context(), "prevented_db_fetch")
				response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "role not found", nil)
				return
			}
			observability.RecordAdminRBACMutation(r.Context(), "role", "update", "error")
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load role", nil)
			return
		}
		observability.RecordAdminNegativeLookupEffectiveness(r.Context(), "stale_false_positive")
		before = cachedRole
	} else {
		before, err = h.roleRepo.FindByID(roleID)
		if err != nil {
			if errors.Is(err, repository.ErrRoleNotFound) {
				h.writeNegativeLookupCache(r, roleNegativeLookupNamespace, roleCacheKey)
				response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "role not found", nil)
				return
			}
			observability.RecordAdminRBACMutation(r.Context(), "role", "update", "error")
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load role", nil)
			return
		}
	}
	if h.isProtectedRole(before.Name) {
		observability.RecordAdminRBACMutation(r.Context(), "role", "update", "rejected")
		response.Error(w, r, http.StatusForbidden, "FORBIDDEN", "protected role cannot be modified", nil)
		return
	}

	var body struct {
		Name        *string  `json:"name"`
		Description *string  `json:"description"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}

	newRole := *before
	if body.Name != nil {
		newRole.Name = strings.TrimSpace(*body.Name)
	}
	if body.Description != nil {
		newRole.Description = strings.TrimSpace(*body.Description)
	}
	newPermissions := permissionsToStrings(before.Permissions)
	permIDs := make([]uint, 0, len(before.Permissions))
	for _, p := range before.Permissions {
		permIDs = append(permIDs, p.ID)
	}
	if body.Permissions != nil {
		pairs, err := parsePermissionPairs(body.Permissions)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
			return
		}
		perms, err := h.permRepo.FindByPairs(pairs)
		if err != nil {
			observability.RecordAdminRBACMutation(r.Context(), "role", "update", "error")
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load permissions", nil)
			return
		}
		if len(perms) != len(pairs) {
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "one or more permissions do not exist", nil)
			return
		}
		newPermissions = body.Permissions
		permIDs = permIDs[:0]
		for _, p := range perms {
			permIDs = append(permIDs, p.ID)
		}
	}

	actorID, err := actorIDFromRequest(r)
	if err != nil {
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid actor", nil)
		return
	}
	if h.wouldLockOutRoleMutation(actorID, roleID, requiredPermissionForPath(r.URL.Path), newPermissions) {
		observability.RecordAdminRBACMutation(r.Context(), "role", "update", "rejected")
		response.Error(w, r, http.StatusForbidden, "FORBIDDEN", "mutation would remove caller required permission", nil)
		return
	}

	if err := h.roleRepo.Update(&domain.Role{ID: roleID, Name: newRole.Name, Description: newRole.Description}, permIDs); err != nil {
		if isConflictError(err) {
			observability.RecordAdminRBACMutation(r.Context(), "role", "update", "rejected")
			response.Error(w, r, http.StatusConflict, "CONFLICT", "role name already exists", nil)
			return
		}
		observability.RecordAdminRBACMutation(r.Context(), "role", "update", "error")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to update role", nil)
		return
	}

	updated, _ := h.roleRepo.FindByID(roleID)
	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "admin.role.update",
		ActorUserID: adminActorID(r),
		TargetType:  "role",
		TargetID:    strconv.FormatUint(uint64(roleID), 10),
		Action:      "update",
		Outcome:     "success",
		Reason:      "role_updated",
	},
		"before_name", before.Name,
		"after_name", updated.Name,
		"before_permissions", permissionsToStrings(before.Permissions),
		"after_permissions", permissionsToStrings(updated.Permissions),
	)
	observability.RecordAdminRBACMutation(r.Context(), "role", "update", "success")
	h.invalidateRBACPermissionCacheAll(r)
	h.invalidateAdminListCaches(r, "admin.roles.list", "admin.users.list")
	h.invalidateNegativeLookupCaches(r, roleNegativeLookupNamespace)
	response.JSON(w, r, http.StatusOK, updated)
}

func (h *AdminHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := parsePathID(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid role id", nil)
		return
	}
	roleCacheKey := strconv.FormatUint(uint64(roleID), 10)
	var role *domain.Role
	if h.readNegativeLookupCache(r, roleNegativeLookupNamespace, roleCacheKey) {
		cachedRole, findErr := h.roleRepo.FindByID(roleID)
		if findErr != nil {
			if errors.Is(findErr, repository.ErrRoleNotFound) {
				observability.RecordAdminNegativeLookupEffectiveness(r.Context(), "prevented_db_fetch")
				response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "role not found", nil)
				return
			}
			observability.RecordAdminRBACMutation(r.Context(), "role", "delete", "error")
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load role", nil)
			return
		}
		observability.RecordAdminNegativeLookupEffectiveness(r.Context(), "stale_false_positive")
		role = cachedRole
	} else {
		role, err = h.roleRepo.FindByID(roleID)
		if err != nil {
			if errors.Is(err, repository.ErrRoleNotFound) {
				h.writeNegativeLookupCache(r, roleNegativeLookupNamespace, roleCacheKey)
				response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "role not found", nil)
				return
			}
			observability.RecordAdminRBACMutation(r.Context(), "role", "delete", "error")
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load role", nil)
			return
		}
	}
	if h.isProtectedRole(role.Name) {
		observability.RecordAdminRBACMutation(r.Context(), "role", "delete", "rejected")
		response.Error(w, r, http.StatusForbidden, "FORBIDDEN", "protected role cannot be deleted", nil)
		return
	}
	actorID, err := actorIDFromRequest(r)
	if err != nil {
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid actor", nil)
		return
	}
	if h.wouldLockOutRoleDeletion(actorID, roleID, requiredPermissionForPath(r.URL.Path)) {
		observability.RecordAdminRBACMutation(r.Context(), "role", "delete", "rejected")
		response.Error(w, r, http.StatusForbidden, "FORBIDDEN", "mutation would remove caller required permission", nil)
		return
	}
	if err := h.roleRepo.DeleteByID(roleID); err != nil {
		if errors.Is(err, repository.ErrRoleNotFound) {
			response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "role not found", nil)
			return
		}
		observability.RecordAdminRBACMutation(r.Context(), "role", "delete", "error")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to delete role", nil)
		return
	}
	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "admin.role.delete",
		ActorUserID: adminActorID(r),
		TargetType:  "role",
		TargetID:    strconv.FormatUint(uint64(roleID), 10),
		Action:      "delete",
		Outcome:     "success",
		Reason:      "role_deleted",
	}, "role_name", role.Name)
	observability.RecordAdminRBACMutation(r.Context(), "role", "delete", "success")
	h.invalidateRBACPermissionCacheAll(r)
	h.invalidateAdminListCaches(r, "admin.roles.list", "admin.users.list")
	h.invalidateNegativeLookupCaches(r, roleNegativeLookupNamespace)
	response.JSON(w, r, http.StatusOK, map[string]any{"role_id": roleID, "status": "deleted"})
}

func (h *AdminHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAdminListRequestDuration(r.Context(), "admin.permissions", status, time.Since(start))
	}()

	cacheNamespace := "admin.permissions.list"
	cacheKey := h.adminListCacheKey(r, cacheNamespace)
	if cachedData, ok := h.readAdminListCache(r, cacheNamespace, cacheKey); ok {
		status = h.respondAdminListWithConditionalETag(w, r, cacheNamespace, nil, cachedData)
		return
	}

	pageReq, err := parsePageRequest(r)
	if err != nil {
		status = "bad_request"
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}
	observability.RecordAdminListPageSize(r.Context(), "admin.permissions", pageReq.PageSize)
	sortBy, sortOrder, err := parseSortParams(r, "created_at", map[string]struct{}{
		"id":         {},
		"created_at": {},
		"updated_at": {},
		"resource":   {},
		"action":     {},
	})
	if err != nil {
		status = "bad_request"
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}
	filterResource := strings.TrimSpace(r.URL.Query().Get("resource"))
	filterAction := strings.TrimSpace(r.URL.Query().Get("action"))
	sfKey := cacheNamespace + "|" + cacheKey
	result, err, shared := h.adminListSingleGroup.Do(sfKey, func() (interface{}, error) {
		permsPage, err := h.permRepo.ListPaged(pageReq, sortBy, sortOrder, filterResource, filterAction)
		if err != nil {
			return nil, err
		}
		payload := paginatedData(permsPage.Items, permsPage.Page, permsPage.PageSize, permsPage.Total, permsPage.TotalPages)
		h.writeAdminListCache(r, cacheNamespace, cacheKey, payload)
		return payload, nil
	})
	if shared {
		observability.RecordAdminListCacheEvent(r.Context(), cacheNamespace, "singleflight_shared")
	} else {
		observability.RecordAdminListCacheEvent(r.Context(), cacheNamespace, "singleflight_leader")
	}
	if err != nil {
		observability.RecordAdminListCacheEvent(r.Context(), cacheNamespace, "error")
		status = "error"
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to list permissions", nil)
		return
	}
	payload, ok := result.(map[string]any)
	if !ok {
		status = "error"
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to encode response", nil)
		return
	}
	status = h.respondAdminListWithConditionalETag(w, r, cacheNamespace, payload, nil)
}

func (h *AdminHandler) CreatePermission(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Resource string `json:"resource"`
		Action   string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	resource, action, err := validatePermissionParts(body.Resource, body.Action)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}
	permission := &domain.Permission{Resource: resource, Action: action}
	if err := h.permRepo.Create(permission); err != nil {
		if isConflictError(err) {
			observability.RecordAdminRBACMutation(r.Context(), "permission", "create", "rejected")
			response.Error(w, r, http.StatusConflict, "CONFLICT", "permission already exists", nil)
			return
		}
		observability.RecordAdminRBACMutation(r.Context(), "permission", "create", "error")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to create permission", nil)
		return
	}
	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "admin.permission.create",
		ActorUserID: adminActorID(r),
		TargetType:  "permission",
		TargetID:    strconv.FormatUint(uint64(permission.ID), 10),
		Action:      "create",
		Outcome:     "success",
		Reason:      "permission_created",
	}, "permission", resource+":"+action)
	observability.RecordAdminRBACMutation(r.Context(), "permission", "create", "success")
	h.invalidateRBACPermissionCacheAll(r)
	h.invalidateAdminListCaches(r, "admin.permissions.list", "admin.roles.list")
	h.invalidateNegativeLookupCaches(r, permissionNegativeLookupNamespace)
	response.JSON(w, r, http.StatusCreated, permission)
}

func (h *AdminHandler) UpdatePermission(w http.ResponseWriter, r *http.Request) {
	permID, err := parsePathID(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid permission id", nil)
		return
	}
	permCacheKey := strconv.FormatUint(uint64(permID), 10)
	var before *domain.Permission
	if h.readNegativeLookupCache(r, permissionNegativeLookupNamespace, permCacheKey) {
		cachedPerm, findErr := h.permRepo.FindByID(permID)
		if findErr != nil {
			if errors.Is(findErr, repository.ErrPermissionNotFound) {
				observability.RecordAdminNegativeLookupEffectiveness(r.Context(), "prevented_db_fetch")
				response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "permission not found", nil)
				return
			}
			observability.RecordAdminRBACMutation(r.Context(), "permission", "update", "error")
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load permission", nil)
			return
		}
		observability.RecordAdminNegativeLookupEffectiveness(r.Context(), "stale_false_positive")
		before = cachedPerm
	} else {
		before, err = h.permRepo.FindByID(permID)
		if err != nil {
			if errors.Is(err, repository.ErrPermissionNotFound) {
				h.writeNegativeLookupCache(r, permissionNegativeLookupNamespace, permCacheKey)
				response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "permission not found", nil)
				return
			}
			observability.RecordAdminRBACMutation(r.Context(), "permission", "update", "error")
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load permission", nil)
			return
		}
	}
	if h.isProtectedPermission(before.Resource + ":" + before.Action) {
		observability.RecordAdminRBACMutation(r.Context(), "permission", "update", "rejected")
		response.Error(w, r, http.StatusForbidden, "FORBIDDEN", "protected permission cannot be modified", nil)
		return
	}

	var body struct {
		Resource string `json:"resource"`
		Action   string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	resource, action, err := validatePermissionParts(body.Resource, body.Action)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}

	actorID, err := actorIDFromRequest(r)
	if err != nil {
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid actor", nil)
		return
	}
	required := requiredPermissionForPath(r.URL.Path)
	if h.wouldLockOutPermissionMutation(actorID, before.Resource+":"+before.Action, resource+":"+action, required) {
		observability.RecordAdminRBACMutation(r.Context(), "permission", "update", "rejected")
		response.Error(w, r, http.StatusForbidden, "FORBIDDEN", "mutation would remove caller required permission", nil)
		return
	}

	if err := h.permRepo.Update(&domain.Permission{ID: permID, Resource: resource, Action: action}); err != nil {
		if isConflictError(err) {
			observability.RecordAdminRBACMutation(r.Context(), "permission", "update", "rejected")
			response.Error(w, r, http.StatusConflict, "CONFLICT", "permission already exists", nil)
			return
		}
		if errors.Is(err, repository.ErrPermissionNotFound) {
			response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "permission not found", nil)
			return
		}
		observability.RecordAdminRBACMutation(r.Context(), "permission", "update", "error")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to update permission", nil)
		return
	}
	updated, _ := h.permRepo.FindByID(permID)
	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "admin.permission.update",
		ActorUserID: adminActorID(r),
		TargetType:  "permission",
		TargetID:    strconv.FormatUint(uint64(permID), 10),
		Action:      "update",
		Outcome:     "success",
		Reason:      "permission_updated",
	}, "before", before.Resource+":"+before.Action, "after", updated.Resource+":"+updated.Action)
	observability.RecordAdminRBACMutation(r.Context(), "permission", "update", "success")
	h.invalidateRBACPermissionCacheAll(r)
	h.invalidateAdminListCaches(r, "admin.permissions.list", "admin.roles.list")
	h.invalidateNegativeLookupCaches(r, permissionNegativeLookupNamespace)
	response.JSON(w, r, http.StatusOK, updated)
}

func (h *AdminHandler) DeletePermission(w http.ResponseWriter, r *http.Request) {
	permID, err := parsePathID(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid permission id", nil)
		return
	}
	permCacheKey := strconv.FormatUint(uint64(permID), 10)
	var perm *domain.Permission
	if h.readNegativeLookupCache(r, permissionNegativeLookupNamespace, permCacheKey) {
		cachedPerm, findErr := h.permRepo.FindByID(permID)
		if findErr != nil {
			if errors.Is(findErr, repository.ErrPermissionNotFound) {
				observability.RecordAdminNegativeLookupEffectiveness(r.Context(), "prevented_db_fetch")
				response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "permission not found", nil)
				return
			}
			observability.RecordAdminRBACMutation(r.Context(), "permission", "delete", "error")
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load permission", nil)
			return
		}
		observability.RecordAdminNegativeLookupEffectiveness(r.Context(), "stale_false_positive")
		perm = cachedPerm
	} else {
		perm, err = h.permRepo.FindByID(permID)
		if err != nil {
			if errors.Is(err, repository.ErrPermissionNotFound) {
				h.writeNegativeLookupCache(r, permissionNegativeLookupNamespace, permCacheKey)
				response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "permission not found", nil)
				return
			}
			observability.RecordAdminRBACMutation(r.Context(), "permission", "delete", "error")
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load permission", nil)
			return
		}
	}
	permToken := perm.Resource + ":" + perm.Action
	if h.isProtectedPermission(permToken) {
		observability.RecordAdminRBACMutation(r.Context(), "permission", "delete", "rejected")
		response.Error(w, r, http.StatusForbidden, "FORBIDDEN", "protected permission cannot be deleted", nil)
		return
	}
	actorID, err := actorIDFromRequest(r)
	if err != nil {
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid actor", nil)
		return
	}
	required := requiredPermissionForPath(r.URL.Path)
	if h.wouldLockOutPermissionDeletion(actorID, permToken, required) {
		observability.RecordAdminRBACMutation(r.Context(), "permission", "delete", "rejected")
		response.Error(w, r, http.StatusForbidden, "FORBIDDEN", "mutation would remove caller required permission", nil)
		return
	}
	if err := h.permRepo.DeleteByID(permID); err != nil {
		if errors.Is(err, repository.ErrPermissionNotFound) {
			response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "permission not found", nil)
			return
		}
		observability.RecordAdminRBACMutation(r.Context(), "permission", "delete", "error")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to delete permission", nil)
		return
	}
	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "admin.permission.delete",
		ActorUserID: adminActorID(r),
		TargetType:  "permission",
		TargetID:    strconv.FormatUint(uint64(permID), 10),
		Action:      "delete",
		Outcome:     "success",
		Reason:      "permission_deleted",
	}, "permission", permToken)
	observability.RecordAdminRBACMutation(r.Context(), "permission", "delete", "success")
	h.invalidateRBACPermissionCacheAll(r)
	h.invalidateAdminListCaches(r, "admin.permissions.list", "admin.roles.list")
	h.invalidateNegativeLookupCaches(r, permissionNegativeLookupNamespace)
	response.JSON(w, r, http.StatusOK, map[string]any{"permission_id": permID, "status": "deleted"})
}

func (h *AdminHandler) SyncRBAC(w http.ResponseWriter, r *http.Request) {
	report, err := database.SeedSync(h.db, h.cfg.BootstrapAdminEmail)
	if err != nil {
		observability.RecordAdminRBACMutation(r.Context(), "sync", "sync", "error")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "rbac sync failed", nil)
		return
	}
	actorID, _ := actorIDFromRequest(r)
	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "admin.rbac.sync",
		ActorUserID: observability.ActorUserID(actorID),
		TargetType:  "rbac",
		TargetID:    "seed",
		Action:      "sync",
		Outcome:     "success",
		Reason:      "seed_reconciled",
	}, "report", report)
	observability.RecordAdminRBACMutation(r.Context(), "sync", "sync", "success")
	observability.RecordAdminRBACSyncReport(r.Context(), "created_permissions", float64(report.CreatedPermissions))
	observability.RecordAdminRBACSyncReport(r.Context(), "created_roles", float64(report.CreatedRoles))
	observability.RecordAdminRBACSyncReport(r.Context(), "bound_permissions", float64(report.BoundPermissions))
	if report.Noop {
		observability.RecordAdminRBACSyncReport(r.Context(), "noop", 1)
	} else {
		observability.RecordAdminRBACSyncReport(r.Context(), "noop", 0)
	}
	h.invalidateRBACPermissionCacheAll(r)
	h.invalidateAdminListCaches(r, "admin.users.list", "admin.roles.list", "admin.permissions.list")
	h.invalidateNegativeLookupCaches(r, roleNegativeLookupNamespace, permissionNegativeLookupNamespace)
	response.JSON(w, r, http.StatusOK, report)
}

func (h *AdminHandler) isProtectedRole(name string) bool {
	_, ok := h.protectedRoles[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func (h *AdminHandler) isProtectedPermission(token string) bool {
	_, ok := h.protectedPermissions[strings.ToLower(strings.TrimSpace(token))]
	return ok
}

func (h *AdminHandler) wouldLockOutRoleMutation(actorID, roleID uint, requiredPerm string, newRolePermissions []string) bool {
	if requiredPerm == "" {
		return false
	}
	actor, perms, err := h.userSvc.GetByID(actorID)
	if err != nil {
		return false
	}
	if !h.rbac.HasPermission(perms, requiredPerm) {
		return false
	}
	next := make(map[string]struct{})
	newSet := make(map[string]struct{}, len(newRolePermissions))
	for _, p := range newRolePermissions {
		newSet[strings.ToLower(strings.TrimSpace(p))] = struct{}{}
	}
	for _, role := range actor.Roles {
		if role.ID == roleID {
			for p := range newSet {
				next[p] = struct{}{}
			}
			continue
		}
		for _, p := range role.Permissions {
			next[strings.ToLower(p.Resource+":"+p.Action)] = struct{}{}
		}
	}
	_, ok := next[strings.ToLower(requiredPerm)]
	return !ok
}

func (h *AdminHandler) wouldLockOutRoleDeletion(actorID, roleID uint, requiredPerm string) bool {
	if requiredPerm == "" {
		return false
	}
	actor, perms, err := h.userSvc.GetByID(actorID)
	if err != nil {
		return false
	}
	if !h.rbac.HasPermission(perms, requiredPerm) {
		return false
	}
	next := make(map[string]struct{})
	for _, role := range actor.Roles {
		if role.ID == roleID {
			continue
		}
		for _, p := range role.Permissions {
			next[strings.ToLower(p.Resource+":"+p.Action)] = struct{}{}
		}
	}
	_, ok := next[strings.ToLower(requiredPerm)]
	return !ok
}

func (h *AdminHandler) wouldLockOutPermissionMutation(actorID uint, before, after, requiredPerm string) bool {
	if requiredPerm == "" {
		return false
	}
	_, perms, err := h.userSvc.GetByID(actorID)
	if err != nil {
		return false
	}
	next := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		next[strings.ToLower(p)] = struct{}{}
	}
	delete(next, strings.ToLower(before))
	next[strings.ToLower(after)] = struct{}{}
	_, ok := next[strings.ToLower(requiredPerm)]
	return !ok
}

func (h *AdminHandler) wouldLockOutPermissionDeletion(actorID uint, permToken, requiredPerm string) bool {
	if requiredPerm == "" {
		return false
	}
	_, perms, err := h.userSvc.GetByID(actorID)
	if err != nil {
		return false
	}
	next := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		next[strings.ToLower(p)] = struct{}{}
	}
	delete(next, strings.ToLower(permToken))
	_, ok := next[strings.ToLower(requiredPerm)]
	return !ok
}

func requiredPermissionForPath(path string) string {
	if strings.Contains(path, "/permissions") {
		return "permissions:write"
	}
	if strings.Contains(path, "/roles") || strings.Contains(path, "/rbac/sync") {
		return "roles:write"
	}
	return ""
}

func permissionsToStrings(perms []domain.Permission) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, p.Resource+":"+p.Action)
	}
	return out
}

func parsePermissionPairs(perms []string) ([][2]string, error) {
	pairs := make([][2]string, 0, len(perms))
	seen := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		parts := strings.SplitN(strings.TrimSpace(p), ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("permission format must be resource:action")
		}
		resource, action, err := validatePermissionParts(parts[0], parts[1])
		if err != nil {
			return nil, err
		}
		token := resource + ":" + action
		if _, ok := seen[token]; ok {
			continue
		}
		seen[token] = struct{}{}
		pairs = append(pairs, [2]string{resource, action})
	}
	return pairs, nil
}

func validatePermissionParts(resource, action string) (string, string, error) {
	resource = strings.ToLower(strings.TrimSpace(resource))
	action = strings.ToLower(strings.TrimSpace(action))
	if !permissionPartRe.MatchString(resource) || !permissionPartRe.MatchString(action) {
		return "", "", fmt.Errorf("permission format must be resource:action")
	}
	return resource, action, nil
}

func actorIDFromRequest(r *http.Request) (uint, error) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		return 0, errors.New("missing auth context")
	}
	id64, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return 0, err
	}
	return uint(id64), nil
}

func adminActorID(r *http.Request) string {
	actorID, err := actorIDFromRequest(r)
	if err != nil {
		return "anonymous"
	}
	return observability.ActorUserID(actorID)
}

func parsePathID(input string) (uint, error) {
	trimmed := strings.TrimSpace(input)
	n, err := strconv.ParseUint(trimmed, 10, 64)
	if err != nil {
		return 0, err
	}
	return uint(n), nil
}

func isConflictError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate") || strings.Contains(msg, "unique")
}

func parsePageRequest(r *http.Request) (repository.PageRequest, error) {
	page := repository.DefaultPage
	pageSize := repository.DefaultPageSize
	if raw := strings.TrimSpace(r.URL.Query().Get("page")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 {
			return repository.PageRequest{}, errors.New("page must be a positive integer")
		}
		page = v
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("page_size")); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 1 {
			return repository.PageRequest{}, errors.New("page_size must be a positive integer")
		}
		if v > repository.MaxPageSize {
			return repository.PageRequest{}, fmt.Errorf("page_size must be <= %d", repository.MaxPageSize)
		}
		pageSize = v
	}
	return repository.PageRequest{Page: page, PageSize: pageSize}, nil
}

func parseSortParams(r *http.Request, defaultField string, allowed map[string]struct{}) (string, string, error) {
	sortBy := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort_by")))
	if sortBy == "" {
		sortBy = defaultField
	}
	if _, ok := allowed[sortBy]; !ok {
		return "", "", fmt.Errorf("invalid sort_by: %s", sortBy)
	}

	sortOrder := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("sort_order")))
	if sortOrder == "" {
		sortOrder = "desc"
	}
	if sortOrder != "asc" && sortOrder != "desc" {
		return "", "", errors.New("sort_order must be asc or desc")
	}
	return sortBy, sortOrder, nil
}

func paginatedData[T any](items []T, page, pageSize int, total int64, totalPages int) map[string]any {
	return map[string]any{
		"items": items,
		"pagination": map[string]any{
			"page":        page,
			"page_size":   pageSize,
			"total":       total,
			"total_pages": totalPages,
		},
	}
}

func (h *AdminHandler) adminListCacheKey(r *http.Request, namespace string) string {
	actor := adminActorID(r)
	query := normalizeQueryValues(r.URL.Query())
	return namespace + "|actor=" + actor + "|query=" + query
}

func (h *AdminHandler) readAdminListCache(r *http.Request, namespace, key string) (json.RawMessage, bool) {
	if h.adminListCache == nil || h.adminListCacheTTL <= 0 {
		return nil, false
	}
	var (
		cached []byte
		ok     bool
		err    error
	)
	if cacheWithAge, hasAge := h.adminListCache.(service.AdminListCacheStoreWithAge); hasAge {
		var age time.Duration
		cached, ok, age, err = cacheWithAge.GetWithAge(r.Context(), namespace, key)
		if err == nil && ok {
			observability.RecordAdminListCacheEntryAge(r.Context(), namespace, age)
		}
	} else {
		cached, ok, err = h.adminListCache.Get(r.Context(), namespace, key)
	}
	if err != nil {
		observability.RecordAdminListCacheEvent(r.Context(), namespace, "store_error")
		return nil, false
	}
	if !ok {
		observability.RecordAdminListCacheEvent(r.Context(), namespace, "miss")
		return nil, false
	}
	observability.RecordAdminListCacheEvent(r.Context(), namespace, "hit")
	return json.RawMessage(cached), true
}

func (h *AdminHandler) writeAdminListCache(r *http.Request, namespace, key string, payload any) {
	if h.adminListCache == nil || h.adminListCacheTTL <= 0 {
		return
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		observability.RecordAdminListCacheEvent(r.Context(), namespace, "encode_error")
		return
	}
	if err := h.adminListCache.Set(r.Context(), namespace, key, encoded, h.adminListCacheTTL); err != nil {
		observability.RecordAdminListCacheEvent(r.Context(), namespace, "store_error")
		return
	}
	observability.RecordAdminListCacheEvent(r.Context(), namespace, "store")
}

func (h *AdminHandler) invalidateAdminListCaches(r *http.Request, namespaces ...string) {
	if h.adminListCache == nil || len(namespaces) == 0 {
		return
	}
	for _, namespace := range namespaces {
		if namespace == "" {
			continue
		}
		if err := h.adminListCache.InvalidateNamespace(r.Context(), namespace); err != nil {
			observability.RecordAdminListCacheEvent(r.Context(), namespace, "invalidate_error")
			continue
		}
		observability.RecordAdminListCacheEvent(r.Context(), namespace, "invalidate")
	}
}

func (h *AdminHandler) readNegativeLookupCache(r *http.Request, namespace, key string) bool {
	if h.negativeLookupCache == nil || h.negativeLookupTTL <= 0 {
		return false
	}
	ok, err := h.negativeLookupCache.Get(r.Context(), namespace, key)
	if err != nil {
		observability.RecordAdminListCacheEvent(r.Context(), namespace, "negative_store_error")
		return false
	}
	if !ok {
		observability.RecordAdminListCacheEvent(r.Context(), namespace, "negative_miss")
		return false
	}
	observability.RecordAdminListCacheEvent(r.Context(), namespace, "negative_hit")
	return true
}

func (h *AdminHandler) writeNegativeLookupCache(r *http.Request, namespace, key string) {
	if h.negativeLookupCache == nil || h.negativeLookupTTL <= 0 {
		return
	}
	if err := h.negativeLookupCache.Set(r.Context(), namespace, key, h.negativeLookupTTL); err != nil {
		observability.RecordAdminListCacheEvent(r.Context(), namespace, "negative_store_error")
		return
	}
	observability.RecordAdminListCacheEvent(r.Context(), namespace, "negative_store")
}

func (h *AdminHandler) invalidateNegativeLookupCaches(r *http.Request, namespaces ...string) {
	if h.negativeLookupCache == nil || len(namespaces) == 0 {
		return
	}
	for _, namespace := range namespaces {
		if namespace == "" {
			continue
		}
		if err := h.negativeLookupCache.InvalidateNamespace(r.Context(), namespace); err != nil {
			observability.RecordAdminListCacheEvent(r.Context(), namespace, "negative_invalidate_error")
			continue
		}
		observability.RecordAdminListCacheEvent(r.Context(), namespace, "negative_invalidate")
	}
}

func (h *AdminHandler) invalidateRBACPermissionCacheUser(r *http.Request, userID uint) {
	if h.permissionResolver == nil {
		observability.RecordRBACPermissionCacheEvent(r.Context(), "invalidate_user_skipped")
		return
	}
	if err := h.permissionResolver.InvalidateUser(r.Context(), userID); err != nil {
		observability.RecordRBACPermissionCacheEvent(r.Context(), "invalidate_user_error")
		slog.Warn("rbac permission cache user invalidation failed", "user_id", userID, "path", r.URL.Path, "error", err)
		return
	}
	observability.RecordRBACPermissionCacheEvent(r.Context(), "invalidate_user")
}

func (h *AdminHandler) invalidateRBACPermissionCacheAll(r *http.Request) {
	if h.permissionResolver == nil {
		observability.RecordRBACPermissionCacheEvent(r.Context(), "invalidate_all_skipped")
		return
	}
	if err := h.permissionResolver.InvalidateAll(r.Context()); err != nil {
		observability.RecordRBACPermissionCacheEvent(r.Context(), "invalidate_all_error")
		slog.Warn("rbac permission cache global invalidation failed", "path", r.URL.Path, "error", err)
		return
	}
	observability.RecordRBACPermissionCacheEvent(r.Context(), "invalidate_all")
}

func normalizeQueryValues(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	clone := make(url.Values, len(values))
	for k, v := range values {
		c := append([]string(nil), v...)
		clone[k] = c
	}
	return clone.Encode()
}

func (h *AdminHandler) respondAdminListWithConditionalETag(w http.ResponseWriter, r *http.Request, namespace string, payload any, encodedPayload []byte) string {
	encoded := encodedPayload
	if len(encoded) == 0 {
		var err error
		encoded, err = json.Marshal(payload)
		if err != nil {
			observability.RecordAdminListCacheEvent(r.Context(), namespace, "encode_error")
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to encode response", nil)
			return "error"
		}
	}

	etag := buildStrongETag(encoded)
	w.Header().Set("Cache-Control", "private, no-cache")
	w.Header().Set("ETag", etag)
	if matchesIfNoneMatch(r.Header.Get("If-None-Match"), etag) {
		observability.RecordAdminListCacheEvent(r.Context(), namespace, "etag_not_modified")
		w.WriteHeader(http.StatusNotModified)
		return "not_modified"
	}

	observability.RecordAdminListCacheEvent(r.Context(), namespace, "etag_ok")
	if payload != nil {
		response.JSON(w, r, http.StatusOK, payload)
		return "success"
	}
	response.JSON(w, r, http.StatusOK, json.RawMessage(encoded))
	return "success"
}

func buildStrongETag(payload []byte) string {
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("\"%x\"", sum[:])
}

func matchesIfNoneMatch(rawHeader, currentETag string) bool {
	if strings.TrimSpace(rawHeader) == "" {
		return false
	}
	for _, token := range strings.Split(rawHeader, ",") {
		candidate := strings.TrimSpace(token)
		if candidate == "" {
			continue
		}
		if candidate == "*" {
			return true
		}
		candidate = strings.TrimPrefix(candidate, "W/")
		candidate = strings.TrimSpace(candidate)
		if candidate == currentETag {
			return true
		}
	}
	return false
}
