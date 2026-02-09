package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/response"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
)

type AdminHandler struct {
	userSvc  service.UserServiceInterface
	roleRepo repository.RoleRepository
	permRepo repository.PermissionRepository
}

func NewAdminHandler(userSvc service.UserServiceInterface, roleRepo repository.RoleRepository, permRepo repository.PermissionRepository) *AdminHandler {
	return &AdminHandler{userSvc: userSvc, roleRepo: roleRepo, permRepo: permRepo}
}

func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.userSvc.List()
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to list users", nil)
		return
	}
	response.JSON(w, r, http.StatusOK, users)
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
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to set roles", nil)
		return
	}
	observability.Audit(r, "admin.user.roles.updated", "target_user_id", userID, "role_ids", body.RoleIDs)
	observability.RecordAdminRoleMutation(r.Context(), "set_user_roles")
	response.JSON(w, r, http.StatusOK, map[string]any{"user_id": userID, "role_ids": body.RoleIDs})
}

func (h *AdminHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := h.roleRepo.List()
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to list roles", nil)
		return
	}
	response.JSON(w, r, http.StatusOK, roles)
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
	pairs := make([][2]string, 0, len(body.Permissions))
	for _, p := range body.Permissions {
		parts := strings.SplitN(p, ":", 2)
		if len(parts) != 2 {
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "permission format must be resource:action", nil)
			return
		}
		pairs = append(pairs, [2]string{parts[0], parts[1]})
	}
	perms, err := h.permRepo.FindByPairs(pairs)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load permissions", nil)
		return
	}
	permIDs := make([]uint, 0, len(perms))
	for _, p := range perms {
		permIDs = append(permIDs, p.ID)
	}
	role := &domain.Role{Name: body.Name, Description: body.Description}
	if err := h.roleRepo.Create(role, permIDs); err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "failed to create role", nil)
		return
	}
	observability.Audit(r, "admin.role.created", "role_id", role.ID, "role_name", role.Name)
	observability.RecordAdminRoleMutation(r.Context(), "create_role")
	response.JSON(w, r, http.StatusCreated, role)
}

func (h *AdminHandler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := h.permRepo.List()
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to list permissions", nil)
		return
	}
	response.JSON(w, r, http.StatusOK, perms)
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
