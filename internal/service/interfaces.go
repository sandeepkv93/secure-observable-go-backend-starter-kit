package service

import (
	"net/http"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
)

type AuthServiceInterface interface {
	GoogleLoginURL(state string) string
	LoginWithGoogleCode(code, ua, ip string) (*LoginResult, error)
	RegisterLocal(email, name, password, ua, ip string) (*LoginResult, error)
	LoginWithLocalPassword(email, password, ua, ip string) (*LoginResult, error)
	RequestLocalEmailVerification(email string) error
	ConfirmLocalEmailVerification(token string) error
	ForgotLocalPassword(email string) error
	ResetLocalPassword(token, newPassword string) error
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

type SessionServiceInterface interface {
	ListActiveSessions(userID uint, currentSessionID uint) ([]SessionView, error)
	ResolveCurrentSessionID(r *http.Request, claims *security.Claims, userID uint) (uint, error)
	RevokeSession(userID, sessionID uint) (string, error)
	RevokeOtherSessions(userID, currentSessionID uint) (int64, error)
}
