package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"gorm.io/gorm"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/database"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/response"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
)

var permissionPartRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

type AdminHandler struct {
	userSvc              service.UserServiceInterface
	userRepo             repository.UserRepository
	roleRepo             repository.RoleRepository
	permRepo             repository.PermissionRepository
	rbac                 service.RBACAuthorizer
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
		db:                   db,
		cfg:                  cfg,
		protectedRoles:       protectedRoles,
		protectedPermissions: protectedPerms,
	}
}

func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	pageReq, err := parsePageRequest(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}
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
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}

	filterEmail := strings.TrimSpace(r.URL.Query().Get("email"))
	filterStatus := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
	filterRole := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("role")))
	usersPage, err := h.userRepo.ListPaged(repository.UserListQuery{
		PageRequest: pageReq,
		SortBy:      sortBy,
		SortOrder:   sortOrder,
		Email:       filterEmail,
		Status:      filterStatus,
		Role:        filterRole,
	})
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to list users", nil)
		return
	}
	response.JSON(w, r, http.StatusOK, paginatedData(usersPage.Items, usersPage.Page, usersPage.PageSize, usersPage.Total, usersPage.TotalPages))
}

func (h *AdminHandler) SetUserRoles(w http.ResponseWriter, r *http.Request) {
	idParam := chi.URLParam(r, "id")
	var userID uint
	if _, err := fmtSscanfUint(idParam, &userID); err != nil {
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
	observability.Audit(r, "admin.user.roles.updated", "target_user_id", userID, "role_ids", body.RoleIDs)
	observability.RecordAdminRBACMutation(r.Context(), "user_role", "set_user_roles", "success")
	response.JSON(w, r, http.StatusOK, map[string]any{"user_id": userID, "role_ids": body.RoleIDs})
}

func (h *AdminHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	pageReq, err := parsePageRequest(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}
	sortBy, sortOrder, err := parseSortParams(r, "created_at", map[string]struct{}{
		"id":         {},
		"created_at": {},
		"updated_at": {},
		"name":       {},
	})
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}
	filterName := strings.TrimSpace(r.URL.Query().Get("name"))
	rolesPage, err := h.roleRepo.ListPaged(pageReq, sortBy, sortOrder, filterName)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to list roles", nil)
		return
	}
	response.JSON(w, r, http.StatusOK, paginatedData(rolesPage.Items, rolesPage.Page, rolesPage.PageSize, rolesPage.Total, rolesPage.TotalPages))
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
	observability.Audit(r, "admin.role.created", "role_id", role.ID, "role_name", role.Name, "after_permissions", body.Permissions)
	observability.RecordAdminRBACMutation(r.Context(), "role", "create", "success")
	response.JSON(w, r, http.StatusCreated, role)
}

func (h *AdminHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := parsePathID(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid role id", nil)
		return
	}
	before, err := h.roleRepo.FindByID(roleID)
	if err != nil {
		if errors.Is(err, repository.ErrRoleNotFound) {
			response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "role not found", nil)
			return
		}
		observability.RecordAdminRBACMutation(r.Context(), "role", "update", "error")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load role", nil)
		return
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
	observability.Audit(r, "admin.role.updated",
		"role_id", roleID,
		"before_name", before.Name,
		"after_name", updated.Name,
		"before_permissions", permissionsToStrings(before.Permissions),
		"after_permissions", permissionsToStrings(updated.Permissions),
	)
	observability.RecordAdminRBACMutation(r.Context(), "role", "update", "success")
	response.JSON(w, r, http.StatusOK, updated)
}

func (h *AdminHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	roleID, err := parsePathID(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid role id", nil)
		return
	}
	role, err := h.roleRepo.FindByID(roleID)
	if err != nil {
		if errors.Is(err, repository.ErrRoleNotFound) {
			response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "role not found", nil)
			return
		}
		observability.RecordAdminRBACMutation(r.Context(), "role", "delete", "error")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load role", nil)
		return
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
	observability.Audit(r, "admin.role.deleted", "role_id", roleID, "role_name", role.Name)
	observability.RecordAdminRBACMutation(r.Context(), "role", "delete", "success")
	response.JSON(w, r, http.StatusOK, map[string]any{"role_id": roleID, "status": "deleted"})
}

func (h *AdminHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	pageReq, err := parsePageRequest(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}
	sortBy, sortOrder, err := parseSortParams(r, "created_at", map[string]struct{}{
		"id":         {},
		"created_at": {},
		"updated_at": {},
		"resource":   {},
		"action":     {},
	})
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}
	filterResource := strings.TrimSpace(r.URL.Query().Get("resource"))
	filterAction := strings.TrimSpace(r.URL.Query().Get("action"))
	permsPage, err := h.permRepo.ListPaged(pageReq, sortBy, sortOrder, filterResource, filterAction)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to list permissions", nil)
		return
	}
	response.JSON(w, r, http.StatusOK, paginatedData(permsPage.Items, permsPage.Page, permsPage.PageSize, permsPage.Total, permsPage.TotalPages))
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
	observability.Audit(r, "admin.permission.created", "permission_id", permission.ID, "permission", resource+":"+action)
	observability.RecordAdminRBACMutation(r.Context(), "permission", "create", "success")
	response.JSON(w, r, http.StatusCreated, permission)
}

func (h *AdminHandler) UpdatePermission(w http.ResponseWriter, r *http.Request) {
	permID, err := parsePathID(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid permission id", nil)
		return
	}
	before, err := h.permRepo.FindByID(permID)
	if err != nil {
		if errors.Is(err, repository.ErrPermissionNotFound) {
			response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "permission not found", nil)
			return
		}
		observability.RecordAdminRBACMutation(r.Context(), "permission", "update", "error")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load permission", nil)
		return
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
	observability.Audit(r, "admin.permission.updated", "permission_id", permID, "before", before.Resource+":"+before.Action, "after", updated.Resource+":"+updated.Action)
	observability.RecordAdminRBACMutation(r.Context(), "permission", "update", "success")
	response.JSON(w, r, http.StatusOK, updated)
}

func (h *AdminHandler) DeletePermission(w http.ResponseWriter, r *http.Request) {
	permID, err := parsePathID(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid permission id", nil)
		return
	}
	perm, err := h.permRepo.FindByID(permID)
	if err != nil {
		if errors.Is(err, repository.ErrPermissionNotFound) {
			response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "permission not found", nil)
			return
		}
		observability.RecordAdminRBACMutation(r.Context(), "permission", "delete", "error")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load permission", nil)
		return
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
	observability.Audit(r, "admin.permission.deleted", "permission_id", permID, "permission", permToken)
	observability.RecordAdminRBACMutation(r.Context(), "permission", "delete", "success")
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
	observability.Audit(r, "admin.rbac.sync", "actor_user_id", actorID, "report", report)
	observability.RecordAdminRBACMutation(r.Context(), "sync", "sync", "success")
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

func parsePathID(input string) (uint, error) {
	var out uint
	_, err := fmtSscanfUint(input, &out)
	return out, err
}

func fmtSscanfUint(input string, out *uint) (int, error) {
	var n uint64
	count, err := fmt.Sscanf(input, "%d", &n)
	if err != nil {
		return count, err
	}
	*out = uint(n)
	return count, nil
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
