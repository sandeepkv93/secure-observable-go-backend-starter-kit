package service

import (
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/repository"
)

type UserService struct {
	userRepo repository.UserRepository
	rbac     *RBACService
}

func NewUserService(userRepo repository.UserRepository, rbac *RBACService) *UserService {
	return &UserService{userRepo: userRepo, rbac: rbac}
}

func (s *UserService) GetByID(id uint) (*domain.User, []string, error) {
	u, err := s.userRepo.FindByID(id)
	if err != nil {
		return nil, nil, err
	}
	return u, s.rbac.PermissionsFromRoles(u.Roles), nil
}

func (s *UserService) List() ([]domain.User, error) {
	return s.userRepo.List()
}

func (s *UserService) SetRoles(userID uint, roleIDs []uint) error {
	return s.userRepo.SetRoles(userID, roleIDs)
}

func (s *UserService) AddRole(userID, roleID uint) error {
	return s.userRepo.AddRole(userID, roleID)
}
