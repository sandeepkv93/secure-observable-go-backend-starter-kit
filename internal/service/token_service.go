package service

import (
	"fmt"
	"strconv"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
)

type TokenService struct {
	jwtMgr      *security.JWTManager
	sessionRepo repository.SessionRepository
	pepper      string
	accessTTL   time.Duration
	refreshTTL  time.Duration
}

func NewTokenService(jwtMgr *security.JWTManager, sessionRepo repository.SessionRepository, pepper string, accessTTL, refreshTTL time.Duration) *TokenService {
	return &TokenService{jwtMgr: jwtMgr, sessionRepo: sessionRepo, pepper: pepper, accessTTL: accessTTL, refreshTTL: refreshTTL}
}

func (s *TokenService) Issue(user *domain.User, permissions []string, ua, ip string) (access string, refresh string, csrf string, err error) {
	roles := make([]string, 0, len(user.Roles))
	for _, r := range user.Roles {
		roles = append(roles, r.Name)
	}
	access, err = s.jwtMgr.SignAccessToken(user.ID, roles, permissions, s.accessTTL)
	if err != nil {
		return "", "", "", err
	}
	refresh, err = s.jwtMgr.SignRefreshToken(user.ID, s.refreshTTL)
	if err != nil {
		return "", "", "", err
	}
	hash := security.HashRefreshToken(refresh, s.pepper)
	if err := s.sessionRepo.Create(&domain.Session{UserID: user.ID, RefreshTokenHash: hash, UserAgent: ua, IP: ip, ExpiresAt: time.Now().Add(s.refreshTTL)}); err != nil {
		return "", "", "", err
	}
	csrf, err = security.NewCSRFToken()
	if err != nil {
		return "", "", "", err
	}
	return access, refresh, csrf, nil
}

func (s *TokenService) Rotate(refreshToken string, userFetcher func(id uint) (*domain.User, []string, error), ua, ip string) (access string, newRefresh string, csrf string, userID uint, err error) {
	claims, err := s.jwtMgr.ParseRefreshToken(refreshToken)
	if err != nil {
		return "", "", "", 0, err
	}
	hash := security.HashRefreshToken(refreshToken, s.pepper)
	session, err := s.sessionRepo.FindValidByHash(hash)
	if err != nil {
		return "", "", "", 0, err
	}
	if err := s.sessionRepo.RevokeByHash(hash); err != nil {
		return "", "", "", 0, err
	}
	id64, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return "", "", "", 0, fmt.Errorf("invalid subject")
	}
	userID = uint(id64)
	if session.UserID != userID {
		return "", "", "", 0, fmt.Errorf("session mismatch")
	}
	user, perms, err := userFetcher(userID)
	if err != nil {
		return "", "", "", 0, err
	}
	access, newRefresh, csrf, err = s.Issue(user, perms, ua, ip)
	if err != nil {
		return "", "", "", 0, err
	}
	return access, newRefresh, csrf, userID, nil
}

func (s *TokenService) RevokeAll(userID uint) error {
	return s.sessionRepo.RevokeByUserID(userID)
}
