package service

import (
	"context"
	"net/http"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
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

type PermissionResolver interface {
	ResolvePermissions(ctx context.Context, claims *security.Claims) ([]string, error)
	InvalidateUser(ctx context.Context, userID uint) error
	InvalidateAll(ctx context.Context) error
}

type SessionServiceInterface interface {
	ListActiveSessions(userID uint, currentSessionID uint) ([]SessionView, error)
	ResolveCurrentSessionID(r *http.Request, claims *security.Claims, userID uint) (uint, error)
	RevokeSession(userID, sessionID uint) (string, error)
	RevokeOtherSessions(userID, currentSessionID uint) (int64, error)
}

type FeatureFlagService interface {
	EvaluateAll(ctx context.Context, evalCtx FeatureFlagEvaluationContext) ([]FeatureFlagEvaluationResult, error)
	EvaluateByKey(ctx context.Context, key string, evalCtx FeatureFlagEvaluationContext) (*FeatureFlagEvaluationResult, error)
	ListFlags(ctx context.Context) ([]domain.FeatureFlag, error)
	GetFlagByID(ctx context.Context, id uint) (*domain.FeatureFlag, error)
	CreateFlag(ctx context.Context, flag *domain.FeatureFlag) error
	UpdateFlag(ctx context.Context, flag *domain.FeatureFlag) error
	DeleteFlag(ctx context.Context, id uint) error
	ListRules(ctx context.Context, flagID uint) ([]domain.FeatureFlagRule, error)
	CreateRule(ctx context.Context, rule *domain.FeatureFlagRule) error
	UpdateRule(ctx context.Context, rule *domain.FeatureFlagRule) error
	DeleteRule(ctx context.Context, flagID, ruleID uint) error
}

type ProductService interface {
	Create(ctx context.Context, input CreateProductInput) (*domain.Product, error)
	ListPaged(ctx context.Context, req repository.PageRequest) (repository.PageResult[domain.Product], error)
	GetByID(ctx context.Context, id uint) (*domain.Product, error)
	Update(ctx context.Context, id uint, input UpdateProductInput) (*domain.Product, error)
	DeleteByID(ctx context.Context, id uint) error
}
