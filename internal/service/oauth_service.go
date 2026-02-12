package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/repository"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gorm.io/gorm"
)

type OAuthUserInfo struct {
	ProviderUserID string
	Email          string
	Name           string
	Picture        string
	EmailVerified  bool
}

type OAuthProvider interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*oauth2.Token, error)
	FetchUserInfo(ctx context.Context, token *oauth2.Token) (*OAuthUserInfo, error)
}

type GoogleOAuthProvider struct {
	cfg *oauth2.Config
}

func NewGoogleOAuthProvider(cfg *config.Config) *GoogleOAuthProvider {
	return &GoogleOAuthProvider{cfg: &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  cfg.GoogleRedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}}
}

func (p *GoogleOAuthProvider) AuthCodeURL(state string) string {
	return p.cfg.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
}

func (p *GoogleOAuthProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	return p.cfg.Exchange(ctx, code)
}

func (p *GoogleOAuthProvider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*OAuthUserInfo, error) {
	client := p.cfg.Client(ctx, token)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://openidconnect.googleapis.com/v1/userinfo", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo status: %d", resp.StatusCode)
	}
	var body struct {
		Sub           string `json:"sub"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	if body.Sub == "" || body.Email == "" {
		return nil, fmt.Errorf("missing required userinfo fields")
	}
	return &OAuthUserInfo{ProviderUserID: body.Sub, Email: strings.ToLower(body.Email), Name: body.Name, Picture: body.Picture, EmailVerified: body.EmailVerified}, nil
}

type OAuthService struct {
	provider  OAuthProvider
	userRepo  repository.UserRepository
	oauthRepo repository.OAuthRepository
	roleRepo  repository.RoleRepository
}

func NewOAuthService(provider OAuthProvider, userRepo repository.UserRepository, oauthRepo repository.OAuthRepository, roleRepo repository.RoleRepository) *OAuthService {
	return &OAuthService{provider: provider, userRepo: userRepo, oauthRepo: oauthRepo, roleRepo: roleRepo}
}

func (s *OAuthService) LoginURL(state string) string {
	return s.provider.AuthCodeURL(state)
}

func (s *OAuthService) HandleGoogleCallback(ctx context.Context, code string) (*domain.User, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	exchangeStart := time.Now()
	token, err := s.provider.Exchange(ctx, code)
	observability.RecordGoogleOAuthRequestDuration(ctx, "exchange", oauthStatus(err), time.Since(exchangeStart))
	if err != nil {
		observability.RecordGoogleOAuthError(ctx, classifyOAuthError(err))
		return nil, err
	}
	userInfoStart := time.Now()
	info, err := s.provider.FetchUserInfo(ctx, token)
	observability.RecordGoogleOAuthRequestDuration(ctx, "userinfo", oauthStatus(err), time.Since(userInfoStart))
	if err != nil {
		observability.RecordGoogleOAuthError(ctx, classifyOAuthError(err))
		return nil, err
	}
	if info == nil {
		observability.RecordGoogleOAuthError(ctx, "invalid_userinfo")
		return nil, fmt.Errorf("missing required userinfo fields")
	}

	if !info.EmailVerified {
		observability.RecordGoogleOAuthError(ctx, "email_not_verified")
		return nil, fmt.Errorf("google email not verified")
	}

	var user *domain.User
	acct, err := s.oauthRepo.FindByProvider("google", info.ProviderUserID)
	switch err {
	case nil:
		user, err = s.userRepo.FindByID(acct.UserID)
		if err != nil {
			return nil, err
		}
	case gorm.ErrRecordNotFound:
		u, findErr := s.userRepo.FindByEmail(info.Email)
		switch findErr {
		case nil:
			user = u
		case gorm.ErrRecordNotFound:
			user = &domain.User{Email: info.Email, Name: info.Name, AvatarURL: info.Picture, Status: "active"}
			if err := s.userRepo.Create(user); err != nil {
				return nil, err
			}
			userRole, err := s.roleRepo.FindByName("user")
			if err == nil {
				_ = s.userRepo.AddRole(user.ID, userRole.ID)
			}
		default:
			return nil, findErr
		}
		if err := s.oauthRepo.Create(&domain.OAuthAccount{UserID: user.ID, Provider: "google", ProviderUserID: info.ProviderUserID, EmailVerified: true}); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}

	user.Name = info.Name
	user.AvatarURL = info.Picture
	if err := s.userRepo.Update(user); err != nil {
		return nil, err
	}
	return s.userRepo.FindByID(user.ID)
}

func oauthStatus(err error) string {
	if err != nil {
		return "error"
	}
	return "success"
}

func classifyOAuthError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.Canceled) {
		return "context_canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "userinfo status:"):
		return "userinfo_status"
	case strings.Contains(msg, "missing required userinfo fields"):
		return "invalid_userinfo"
	case strings.Contains(msg, "oauth2"):
		return "oauth2_exchange"
	default:
		return "other"
	}
}
