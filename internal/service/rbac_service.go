package service

import "github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"

type RBACService struct{}

func NewRBACService() *RBACService { return &RBACService{} }

func (s *RBACService) PermissionsFromRoles(roles []domain.Role) []string {
	set := map[string]struct{}{}
	for _, r := range roles {
		for _, p := range r.Permissions {
			set[p.Resource+":"+p.Action] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}

func (s *RBACService) HasPermission(permissions []string, required string) bool {
	for _, p := range permissions {
		if p == required {
			return true
		}
	}
	return false
}
