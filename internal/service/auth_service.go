package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
)

type AuthService struct {
	cfg      *config.Config
	oauthSvc *OAuthService
	tokenSvc *TokenService
	userSvc  *UserService
	rbacSvc  *RBACService
}

type LoginResult struct {
	User         *domain.User `json:"user"`
	AccessToken  string       `json:"-"`
	RefreshToken string       `json:"-"`
	CSRFToken    string       `json:"csrf_token"`
	ExpiresAt    time.Time    `json:"expires_at"`
}

func NewAuthService(cfg *config.Config, oauthSvc *OAuthService, tokenSvc *TokenService, userSvc *UserService, rbacSvc *RBACService) *AuthService {
	return &AuthService{cfg: cfg, oauthSvc: oauthSvc, tokenSvc: tokenSvc, userSvc: userSvc, rbacSvc: rbacSvc}
}

func (s *AuthService) GoogleLoginURL(state string) string {
	return s.oauthSvc.LoginURL(state)
}

func (s *AuthService) LoginWithGoogleCode(code, ua, ip string) (*LoginResult, error) {
	user, err := s.oauthSvc.HandleGoogleCallback(context.Background(), code)
	if err != nil {
		return nil, err
	}
	if err := s.assignBootstrapAdminIfNeeded(user); err != nil {
		return nil, err
	}
	user, perms, err := s.userSvc.GetByID(user.ID)
	if err != nil {
		return nil, err
	}
	access, refresh, csrf, err := s.tokenSvc.Issue(user, perms, ua, ip)
	if err != nil {
		return nil, err
	}
	return &LoginResult{User: user, AccessToken: access, RefreshToken: refresh, CSRFToken: csrf, ExpiresAt: time.Now().Add(s.cfg.JWTAccessTTL)}, nil
}

func (s *AuthService) Refresh(refreshToken, ua, ip string) (*LoginResult, error) {
	access, newRefresh, csrf, uid, err := s.tokenSvc.Rotate(refreshToken, func(id uint) (*domain.User, []string, error) {
		return s.userSvc.GetByID(id)
	}, ua, ip)
	if err != nil {
		return nil, err
	}
	u, _, err := s.userSvc.GetByID(uid)
	if err != nil {
		return nil, err
	}
	return &LoginResult{User: u, AccessToken: access, RefreshToken: newRefresh, CSRFToken: csrf, ExpiresAt: time.Now().Add(s.cfg.JWTAccessTTL)}, nil
}

func (s *AuthService) Logout(userID uint) error {
	return s.tokenSvc.RevokeAll(userID)
}

func (s *AuthService) ParseUserID(subject string) (uint, error) {
	id, err := strconv.ParseUint(subject, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid user subject")
	}
	return uint(id), nil
}

func (s *AuthService) assignBootstrapAdminIfNeeded(user *domain.User) error {
	target := strings.TrimSpace(strings.ToLower(s.cfg.BootstrapAdminEmail))
	if target == "" || strings.ToLower(user.Email) != target {
		return nil
	}
	admin, err := s.oauthSvc.roleRepo.FindByName("admin")
	if err != nil {
		return err
	}
	return s.userSvc.AddRole(user.ID, admin.ID)
}
