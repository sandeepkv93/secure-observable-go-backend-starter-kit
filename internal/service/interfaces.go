package service

import "github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"

type AuthServiceInterface interface {
	GoogleLoginURL(state string) string
	LoginWithGoogleCode(code, ua, ip string) (*LoginResult, error)
	RegisterLocal(email, name, password, ua, ip string) (*LoginResult, error)
	LoginWithLocalPassword(email, password, ua, ip string) (*LoginResult, error)
	ChangeLocalPassword(userID uint, currentPassword, newPassword string) error
	Refresh(refreshToken, ua, ip string) (*LoginResult, error)
	Logout(userID uint) error
	ParseUserID(subject string) (uint, error)
}

type UserServiceInterface interface {
	GetByID(id uint) (*domain.User, []string, error)
	List() ([]domain.User, error)
	SetRoles(userID uint, roleIDs []uint) error
}

type RBACAuthorizer interface {
	HasPermission(permissions []string, required string) bool
}
