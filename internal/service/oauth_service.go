package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/domain"
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
	defer resp.Body.Close()
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
	token, err := s.provider.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	info, err := s.provider.FetchUserInfo(ctx, token)
	if err != nil {
		return nil, err
	}

	if !info.EmailVerified {
		return nil, fmt.Errorf("google email not verified")
	}

	var user *domain.User
	acct, err := s.oauthRepo.FindByProvider("google", info.ProviderUserID)
	if err == nil {
		user, err = s.userRepo.FindByID(acct.UserID)
		if err != nil {
			return nil, err
		}
	} else if err == gorm.ErrRecordNotFound {
		u, findErr := s.userRepo.FindByEmail(info.Email)
		if findErr == nil {
			user = u
		} else if findErr == gorm.ErrRecordNotFound {
			user = &domain.User{Email: info.Email, Name: info.Name, AvatarURL: info.Picture, Status: "active"}
			if err := s.userRepo.Create(user); err != nil {
				return nil, err
			}
			userRole, err := s.roleRepo.FindByName("user")
			if err == nil {
				_ = s.userRepo.AddRole(user.ID, userRole.ID)
			}
		} else {
			return nil, findErr
		}
		if err := s.oauthRepo.Create(&domain.OAuthAccount{UserID: user.ID, Provider: "google", ProviderUserID: info.ProviderUserID, EmailVerified: true}); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}

	user.Name = info.Name
	user.AvatarURL = info.Picture
	if err := s.userRepo.Update(user); err != nil {
		return nil, err
	}
	return s.userRepo.FindByID(user.ID)
}
