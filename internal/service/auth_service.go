package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"

	"gorm.io/gorm"
)

type AuthService struct {
	cfg                   *config.Config
	oauthSvc              *OAuthService
	tokenSvc              *TokenService
	userSvc               *UserService
	roleRepo              repository.RoleRepository
	localCredsRepo        repository.LocalCredentialRepository
	verificationTokenRepo repository.VerificationTokenRepository
	verificationNotifier  EmailVerificationNotifier
	passwordResetNotifier PasswordResetNotifier
}

type LoginResult struct {
	User                 *domain.User `json:"user"`
	AccessToken          string       `json:"-"`
	RefreshToken         string       `json:"-"`
	CSRFToken            string       `json:"csrf_token,omitempty"`
	ExpiresAt            time.Time    `json:"expires_at,omitempty"`
	RequiresVerification bool         `json:"requires_verification,omitempty"`
}

var (
	ErrGoogleAuthDisabled   = errors.New("google auth is disabled")
	ErrLocalAuthDisabled    = errors.New("local auth is disabled")
	ErrLocalEmailUnverified = errors.New("email verification required")
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrWeakPassword         = errors.New("password does not meet policy requirements")
	ErrInvalidVerifyToken   = errors.New("invalid or expired verification token")
)

var (
	uppercaseRe = regexp.MustCompile(`[A-Z]`)
	lowercaseRe = regexp.MustCompile(`[a-z]`)
	digitRe     = regexp.MustCompile(`[0-9]`)
	specialRe   = regexp.MustCompile(`[^A-Za-z0-9]`)
)

func NewAuthService(
	cfg *config.Config,
	oauthSvc *OAuthService,
	tokenSvc *TokenService,
	userSvc *UserService,
	roleRepo repository.RoleRepository,
	localCredsRepo repository.LocalCredentialRepository,
	verificationTokenRepo repository.VerificationTokenRepository,
	verificationNotifier EmailVerificationNotifier,
	passwordResetNotifier PasswordResetNotifier,
) *AuthService {
	return &AuthService{
		cfg:                   cfg,
		oauthSvc:              oauthSvc,
		tokenSvc:              tokenSvc,
		userSvc:               userSvc,
		roleRepo:              roleRepo,
		localCredsRepo:        localCredsRepo,
		verificationTokenRepo: verificationTokenRepo,
		verificationNotifier:  verificationNotifier,
		passwordResetNotifier: passwordResetNotifier,
	}
}

func (s *AuthService) GoogleLoginURL(state string) string {
	if !s.cfg.AuthGoogleEnabled {
		return ""
	}
	return s.oauthSvc.LoginURL(state)
}

func (s *AuthService) LoginWithGoogleCode(code, ua, ip string) (*LoginResult, error) {
	if !s.cfg.AuthGoogleEnabled {
		return nil, ErrGoogleAuthDisabled
	}
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

func (s *AuthService) RegisterLocal(email, name, password, ua, ip string) (*LoginResult, error) {
	if !s.cfg.AuthLocalEnabled {
		return nil, ErrLocalAuthDisabled
	}
	email = strings.TrimSpace(strings.ToLower(email))
	name = strings.TrimSpace(name)
	if err := validateEmail(email); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}
	if _, err := s.userSvc.userRepo.FindByEmail(email); err == nil {
		return nil, fmt.Errorf("email already registered")
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	user := &domain.User{Email: email, Name: name, Status: "active"}
	if err := s.userSvc.userRepo.Create(user); err != nil {
		return nil, err
	}
	userRole, err := s.roleRepo.FindByName("user")
	if err == nil {
		_ = s.userSvc.AddRole(user.ID, userRole.ID)
	}

	hash, err := security.HashPassword(password)
	if err != nil {
		return nil, err
	}
	verified := !s.cfg.AuthLocalRequireEmailVerification
	credential := &domain.LocalCredential{
		UserID:        user.ID,
		PasswordHash:  hash,
		EmailVerified: verified,
	}
	if verified {
		now := time.Now().UTC()
		credential.EmailVerifiedAt = &now
	}
	if err := s.localCredsRepo.Create(credential); err != nil {
		return nil, err
	}

	if err := s.assignBootstrapAdminIfNeeded(user); err != nil {
		return nil, err
	}

	freshUser, perms, err := s.userSvc.GetByID(user.ID)
	if err != nil {
		return nil, err
	}
	if !verified {
		return &LoginResult{
			User:                 freshUser,
			RequiresVerification: true,
		}, nil
	}

	access, refresh, csrf, err := s.tokenSvc.Issue(freshUser, perms, ua, ip)
	if err != nil {
		return nil, err
	}
	return &LoginResult{User: freshUser, AccessToken: access, RefreshToken: refresh, CSRFToken: csrf, ExpiresAt: time.Now().Add(s.cfg.JWTAccessTTL)}, nil
}

func (s *AuthService) LoginWithLocalPassword(email, password, ua, ip string) (*LoginResult, error) {
	if !s.cfg.AuthLocalEnabled {
		return nil, ErrLocalAuthDisabled
	}
	email = strings.TrimSpace(strings.ToLower(email))
	cred, err := s.localCredsRepo.FindByEmail(email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	ok, err := security.VerifyPassword(cred.PasswordHash, password)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidCredentials
	}
	if s.cfg.AuthLocalRequireEmailVerification && !cred.EmailVerified {
		return nil, ErrLocalEmailUnverified
	}
	user, perms, err := s.userSvc.GetByID(cred.UserID)
	if err != nil {
		return nil, err
	}
	access, refresh, csrf, err := s.tokenSvc.Issue(user, perms, ua, ip)
	if err != nil {
		return nil, err
	}
	return &LoginResult{User: user, AccessToken: access, RefreshToken: refresh, CSRFToken: csrf, ExpiresAt: time.Now().Add(s.cfg.JWTAccessTTL)}, nil
}

func (s *AuthService) RequestLocalEmailVerification(email string) error {
	if !s.cfg.AuthLocalEnabled {
		return ErrLocalAuthDisabled
	}
	email = strings.TrimSpace(strings.ToLower(email))
	if err := validateEmail(email); err != nil {
		return err
	}

	cred, err := s.localCredsRepo.FindByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	if cred.EmailVerified {
		return nil
	}

	now := time.Now().UTC()
	if err := s.verificationTokenRepo.InvalidateActiveByUserPurpose(cred.UserID, "email_verify", now); err != nil {
		return err
	}

	rawToken, err := security.NewRandomString(32)
	if err != nil {
		return err
	}
	expiresAt := now.Add(s.cfg.AuthEmailVerifyTokenTTL)
	hash := hashVerificationToken(rawToken)
	if err := s.verificationTokenRepo.Create(&domain.VerificationToken{
		UserID:    cred.UserID,
		TokenHash: hash,
		Purpose:   "email_verify",
		ExpiresAt: expiresAt,
	}); err != nil {
		return err
	}

	verifyURL := ""
	if strings.TrimSpace(s.cfg.AuthEmailVerifyBaseURL) != "" {
		u, err := url.Parse(s.cfg.AuthEmailVerifyBaseURL)
		if err != nil {
			return fmt.Errorf("invalid AUTH_EMAIL_VERIFY_BASE_URL: %w", err)
		}
		q := u.Query()
		q.Set("token", rawToken)
		u.RawQuery = q.Encode()
		verifyURL = u.String()
	}

	return s.verificationNotifier.SendEmailVerification(context.Background(), VerificationNotification{
		UserID:          cred.UserID,
		Email:           email,
		Token:           rawToken,
		ExpiresAt:       expiresAt,
		VerificationURL: verifyURL,
	})
}

func (s *AuthService) ConfirmLocalEmailVerification(token string) error {
	if !s.cfg.AuthLocalEnabled {
		return ErrLocalAuthDisabled
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrInvalidVerifyToken
	}
	now := time.Now().UTC()
	record, err := s.verificationTokenRepo.FindActiveByHashPurpose(hashVerificationToken(token), "email_verify", now)
	if err != nil {
		if errors.Is(err, repository.ErrVerificationTokenNotFound) {
			return ErrInvalidVerifyToken
		}
		return err
	}
	if err := s.verificationTokenRepo.Consume(record.ID, record.UserID, now); err != nil {
		if errors.Is(err, repository.ErrVerificationTokenNotFound) {
			return ErrInvalidVerifyToken
		}
		return err
	}
	if err := s.localCredsRepo.MarkEmailVerified(record.UserID); err != nil {
		return err
	}
	return nil
}

func (s *AuthService) ForgotLocalPassword(email string) error {
	if !s.cfg.AuthLocalEnabled {
		return ErrLocalAuthDisabled
	}
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		return nil
	}
	cred, err := s.localCredsRepo.FindByEmail(email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}

	now := time.Now().UTC()
	if err := s.verificationTokenRepo.InvalidateActiveByUserPurpose(cred.UserID, "password_reset", now); err != nil {
		return err
	}

	rawToken, err := security.NewRandomString(32)
	if err != nil {
		return err
	}
	expiresAt := now.Add(s.cfg.AuthPasswordResetTokenTTL)
	if err := s.verificationTokenRepo.Create(&domain.VerificationToken{
		UserID:    cred.UserID,
		TokenHash: hashVerificationToken(rawToken),
		Purpose:   "password_reset",
		ExpiresAt: expiresAt,
	}); err != nil {
		return err
	}

	resetURL := ""
	if strings.TrimSpace(s.cfg.AuthPasswordResetBaseURL) != "" {
		u, err := url.Parse(s.cfg.AuthPasswordResetBaseURL)
		if err != nil {
			return fmt.Errorf("invalid AUTH_PASSWORD_RESET_BASE_URL: %w", err)
		}
		q := u.Query()
		q.Set("token", rawToken)
		u.RawQuery = q.Encode()
		resetURL = u.String()
	}

	return s.passwordResetNotifier.SendPasswordReset(context.Background(), PasswordResetNotification{
		UserID:      cred.UserID,
		Email:       email,
		Token:       rawToken,
		ExpiresAt:   expiresAt,
		PasswordURL: resetURL,
	})
}

func (s *AuthService) ResetLocalPassword(token, newPassword string) error {
	if !s.cfg.AuthLocalEnabled {
		return ErrLocalAuthDisabled
	}
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrInvalidVerifyToken
	}
	now := time.Now().UTC()
	record, err := s.verificationTokenRepo.FindActiveByHashPurpose(hashVerificationToken(token), "password_reset", now)
	if err != nil {
		if errors.Is(err, repository.ErrVerificationTokenNotFound) {
			return ErrInvalidVerifyToken
		}
		return err
	}
	if err := s.verificationTokenRepo.Consume(record.ID, record.UserID, now); err != nil {
		if errors.Is(err, repository.ErrVerificationTokenNotFound) {
			return ErrInvalidVerifyToken
		}
		return err
	}

	newHash, err := security.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.localCredsRepo.UpdatePassword(record.UserID, newHash); err != nil {
		return err
	}
	return s.tokenSvc.RevokeAll(record.UserID, "password_reset")
}

func (s *AuthService) ChangeLocalPassword(userID uint, currentPassword, newPassword string) error {
	if !s.cfg.AuthLocalEnabled {
		return ErrLocalAuthDisabled
	}
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	cred, err := s.localCredsRepo.FindByUserID(userID)
	if err != nil {
		return ErrInvalidCredentials
	}
	ok, err := security.VerifyPassword(cred.PasswordHash, currentPassword)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCredentials
	}
	if currentPassword == newPassword {
		return fmt.Errorf("new password must differ from current password")
	}
	newHash, err := security.HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := s.localCredsRepo.UpdatePassword(userID, newHash); err != nil {
		return err
	}
	return s.tokenSvc.RevokeAll(userID, "password_change")
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
	return s.tokenSvc.RevokeAll(userID, "logout")
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
	admin, err := s.roleRepo.FindByName("admin")
	if err != nil {
		return err
	}
	return s.userSvc.AddRole(user.ID, admin.ID)
}

func validateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return fmt.Errorf("invalid email")
	}
	return nil
}

func validatePassword(password string) error {
	if len(password) < 12 || !uppercaseRe.MatchString(password) ||
		!lowercaseRe.MatchString(password) || !digitRe.MatchString(password) || !specialRe.MatchString(password) {
		return ErrWeakPassword
	}
	return nil
}

func hashVerificationToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
