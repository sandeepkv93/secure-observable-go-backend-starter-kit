package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/config"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
	repogomock "github.com/sandeepkv93/everything-backend-starter-kit/internal/repository/gomock"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	"gorm.io/gorm"
)

func TestAuthServiceRegisterLocalMatrix(t *testing.T) {
	t.Run("local auth disabled", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthLocalEnabled = false

		_, err := fx.auth.RegisterLocal("user@example.com", "User", "StrongPass123!", "ua", "127.0.0.1")
		if !errors.Is(err, ErrLocalAuthDisabled) {
			t.Fatalf("expected ErrLocalAuthDisabled, got %v", err)
		}
	})

	t.Run("invalid email", func(t *testing.T) {
		fx := newAuthServiceFixture()
		_, err := fx.auth.RegisterLocal("bad-email", "User", "StrongPass123!", "ua", "127.0.0.1")
		if err == nil || !strings.Contains(err.Error(), "invalid email") {
			t.Fatalf("expected invalid email error, got %v", err)
		}
	})

	t.Run("missing name", func(t *testing.T) {
		fx := newAuthServiceFixture()
		_, err := fx.auth.RegisterLocal("user@example.com", "   ", "StrongPass123!", "ua", "127.0.0.1")
		if err == nil || !strings.Contains(err.Error(), "name is required") {
			t.Fatalf("expected name required error, got %v", err)
		}
	})

	t.Run("weak password", func(t *testing.T) {
		fx := newAuthServiceFixture()
		_, err := fx.auth.RegisterLocal("user@example.com", "User", "weak", "ua", "127.0.0.1")
		if !errors.Is(err, ErrWeakPassword) {
			t.Fatalf("expected ErrWeakPassword, got %v", err)
		}
	})

	t.Run("duplicate email", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.seedUser("dupe@example.com", "Dupe")

		_, err := fx.auth.RegisterLocal("dupe@example.com", "User", "StrongPass123!", "ua", "127.0.0.1")
		if err == nil || !strings.Contains(err.Error(), "email already registered") {
			t.Fatalf("expected duplicate email error, got %v", err)
		}
	})

	t.Run("verification required branch", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthLocalRequireEmailVerification = true

		res, err := fx.auth.RegisterLocal("verify@example.com", "Verify", "StrongPass123!", "ua", "127.0.0.1")
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		if !res.RequiresVerification {
			t.Fatal("expected RequiresVerification=true")
		}
		if res.AccessToken != "" || res.RefreshToken != "" || res.CSRFToken != "" {
			t.Fatal("expected no tokens when verification is required")
		}
	})

	t.Run("verification disabled issues tokens", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthLocalRequireEmailVerification = false

		res, err := fx.auth.RegisterLocal("login@example.com", "Login", "StrongPass123!", "ua", "127.0.0.1")
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		if res.RequiresVerification {
			t.Fatal("expected RequiresVerification=false")
		}
		if res.AccessToken == "" || res.RefreshToken == "" || res.CSRFToken == "" {
			t.Fatal("expected access/refresh/csrf tokens")
		}
	})

	t.Run("role assignment fallback when user role lookup fails", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.roleRepo.findByNameErr["user"] = errors.New("role backend unavailable")

		_, err := fx.auth.RegisterLocal("fallback@example.com", "Fallback", "StrongPass123!", "ua", "127.0.0.1")
		if err != nil {
			t.Fatalf("register should not fail when user role lookup fails: %v", err)
		}
	})

	t.Run("bootstrap admin assignment success", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.BootstrapAdminEmail = "boss@example.com"
		fx.roleRepo.byName["admin"] = &domain.Role{ID: 99, Name: "admin"}

		_, err := fx.auth.RegisterLocal("boss@example.com", "Boss", "StrongPass123!", "ua", "127.0.0.1")
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		if !fx.userRepo.hasRoleByName("boss@example.com", "admin") {
			t.Fatal("expected bootstrap admin role assignment")
		}
	})

	t.Run("bootstrap admin assignment error", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.BootstrapAdminEmail = "boss@example.com"
		fx.roleRepo.findByNameErr["admin"] = errors.New("admin role lookup failed")

		_, err := fx.auth.RegisterLocal("boss@example.com", "Boss", "StrongPass123!", "ua", "127.0.0.1")
		if err == nil || !strings.Contains(err.Error(), "admin role lookup failed") {
			t.Fatalf("expected bootstrap role lookup error, got %v", err)
		}
	})
}

func TestAuthServiceLoginWithLocalPasswordMatrix(t *testing.T) {
	t.Run("local auth disabled", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthLocalEnabled = false

		_, err := fx.auth.LoginWithLocalPassword("user@example.com", "StrongPass123!", "ua", "127.0.0.1")
		if !errors.Is(err, ErrLocalAuthDisabled) {
			t.Fatalf("expected ErrLocalAuthDisabled, got %v", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.seedLocalUser("user@example.com", "User", "StrongPass123!", true)

		_, err := fx.auth.LoginWithLocalPassword("user@example.com", "WrongPass123!", "ua", "127.0.0.1")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("unverified email rejected when required", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthLocalRequireEmailVerification = true
		fx.seedLocalUser("user@example.com", "User", "StrongPass123!", false)

		_, err := fx.auth.LoginWithLocalPassword("user@example.com", "StrongPass123!", "ua", "127.0.0.1")
		if !errors.Is(err, ErrLocalEmailUnverified) {
			t.Fatalf("expected ErrLocalEmailUnverified, got %v", err)
		}
	})

	t.Run("success issues tokens", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.seedLocalUser("user@example.com", "User", "StrongPass123!", true)

		res, err := fx.auth.LoginWithLocalPassword("user@example.com", "StrongPass123!", "ua", "127.0.0.1")
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		if res.AccessToken == "" || res.RefreshToken == "" || res.CSRFToken == "" {
			t.Fatal("expected non-empty issued tokens")
		}
	})
}

func TestAuthServiceRequestAndConfirmEmailVerificationMatrix(t *testing.T) {
	t.Run("request unknown email is no-op", func(t *testing.T) {
		fx := newAuthServiceFixture()
		if err := fx.auth.RequestLocalEmailVerification("unknown@example.com"); err != nil {
			t.Fatalf("expected no-op success, got %v", err)
		}
		if len(fx.emailNotifier.calls) != 0 {
			t.Fatalf("expected no notifications, got %d", len(fx.emailNotifier.calls))
		}
	})

	t.Run("request already verified is no-op", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.seedLocalUser("verified@example.com", "User", "StrongPass123!", true)

		if err := fx.auth.RequestLocalEmailVerification("verified@example.com"); err != nil {
			t.Fatalf("expected no-op success, got %v", err)
		}
		if fx.verifyRepo.invalidateCalls != 0 {
			t.Fatalf("expected no invalidation call, got %d", fx.verifyRepo.invalidateCalls)
		}
	})

	t.Run("request malformed base url fails", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthEmailVerifyBaseURL = "://bad"
		fx.seedLocalUser("verify@example.com", "User", "StrongPass123!", false)

		err := fx.auth.RequestLocalEmailVerification("verify@example.com")
		if err == nil || !strings.Contains(err.Error(), "invalid AUTH_EMAIL_VERIFY_BASE_URL") {
			t.Fatalf("expected invalid base URL error, got %v", err)
		}
	})

	t.Run("request notifier failure propagates", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthEmailVerifyBaseURL = "https://example.com/verify"
		fx.seedLocalUser("verify@example.com", "User", "StrongPass123!", false)
		fx.emailNotifier.err = errors.New("smtp down")

		err := fx.auth.RequestLocalEmailVerification("verify@example.com")
		if err == nil || !strings.Contains(err.Error(), "smtp down") {
			t.Fatalf("expected notifier error, got %v", err)
		}
	})

	t.Run("request creates token invalidates old and sends URL", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthEmailVerifyBaseURL = "https://example.com/verify"
		uid := fx.seedLocalUser("verify@example.com", "User", "StrongPass123!", false)
		fx.verifyRepo.seedToken(uid, "email_verify", hashVerificationToken("old-token"), time.Now().Add(5*time.Minute), false)

		err := fx.auth.RequestLocalEmailVerification("verify@example.com")
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if fx.verifyRepo.invalidateCalls != 1 {
			t.Fatalf("expected one invalidation, got %d", fx.verifyRepo.invalidateCalls)
		}
		if fx.verifyRepo.createCalls != 1 {
			t.Fatalf("expected one token create, got %d", fx.verifyRepo.createCalls)
		}
		if len(fx.emailNotifier.calls) != 1 {
			t.Fatalf("expected one notification, got %d", len(fx.emailNotifier.calls))
		}
		n := fx.emailNotifier.calls[0]
		if !strings.Contains(n.VerificationURL, "token=") {
			t.Fatalf("expected verification URL with token query, got %q", n.VerificationURL)
		}
	})

	t.Run("confirm empty token", func(t *testing.T) {
		fx := newAuthServiceFixture()
		err := fx.auth.ConfirmLocalEmailVerification("  ")
		if !errors.Is(err, ErrInvalidVerifyToken) {
			t.Fatalf("expected ErrInvalidVerifyToken, got %v", err)
		}
	})

	t.Run("confirm missing token record", func(t *testing.T) {
		fx := newAuthServiceFixture()
		err := fx.auth.ConfirmLocalEmailVerification("missing-token")
		if !errors.Is(err, ErrInvalidVerifyToken) {
			t.Fatalf("expected ErrInvalidVerifyToken, got %v", err)
		}
	})

	t.Run("confirm consume race maps to invalid token", func(t *testing.T) {
		fx := newAuthServiceFixture()
		uid := fx.seedLocalUser("verify@example.com", "User", "StrongPass123!", false)
		raw := "confirm-token"
		fx.verifyRepo.seedToken(uid, "email_verify", hashVerificationToken(raw), time.Now().Add(10*time.Minute), false)
		fx.verifyRepo.consumeErr = repository.ErrVerificationTokenNotFound

		err := fx.auth.ConfirmLocalEmailVerification(raw)
		if !errors.Is(err, ErrInvalidVerifyToken) {
			t.Fatalf("expected ErrInvalidVerifyToken, got %v", err)
		}
	})

	t.Run("confirm mark verified failure", func(t *testing.T) {
		fx := newAuthServiceFixture()
		uid := fx.seedLocalUser("verify@example.com", "User", "StrongPass123!", false)
		raw := "confirm-token"
		fx.verifyRepo.seedToken(uid, "email_verify", hashVerificationToken(raw), time.Now().Add(10*time.Minute), false)
		fx.localRepo.markEmailVerifiedErr = errors.New("write failed")

		err := fx.auth.ConfirmLocalEmailVerification(raw)
		if err == nil || !strings.Contains(err.Error(), "write failed") {
			t.Fatalf("expected mark verified failure, got %v", err)
		}
	})
}

func TestAuthServiceForgotAndResetPasswordMatrix(t *testing.T) {
	t.Run("forgot unknown email is no-op", func(t *testing.T) {
		fx := newAuthServiceFixture()
		if err := fx.auth.ForgotLocalPassword("unknown@example.com"); err != nil {
			t.Fatalf("expected no-op success, got %v", err)
		}
		if len(fx.passwordNotifier.calls) != 0 {
			t.Fatalf("expected no reset notification, got %d", len(fx.passwordNotifier.calls))
		}
	})

	t.Run("forgot malformed base url", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthPasswordResetBaseURL = "://bad"
		fx.seedLocalUser("user@example.com", "User", "StrongPass123!", true)

		err := fx.auth.ForgotLocalPassword("user@example.com")
		if err == nil || !strings.Contains(err.Error(), "invalid AUTH_PASSWORD_RESET_BASE_URL") {
			t.Fatalf("expected malformed reset URL error, got %v", err)
		}
	})

	t.Run("forgot notifier failure", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthPasswordResetBaseURL = "https://example.com/reset"
		fx.seedLocalUser("user@example.com", "User", "StrongPass123!", true)
		fx.passwordNotifier.err = errors.New("provider down")

		err := fx.auth.ForgotLocalPassword("user@example.com")
		if err == nil || !strings.Contains(err.Error(), "provider down") {
			t.Fatalf("expected notifier failure, got %v", err)
		}
	})

	t.Run("forgot success issues token", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthPasswordResetBaseURL = "https://example.com/reset"
		fx.seedLocalUser("user@example.com", "User", "StrongPass123!", true)

		err := fx.auth.ForgotLocalPassword("user@example.com")
		if err != nil {
			t.Fatalf("forgot: %v", err)
		}
		if fx.verifyRepo.createCalls != 1 {
			t.Fatalf("expected token create call, got %d", fx.verifyRepo.createCalls)
		}
		if len(fx.passwordNotifier.calls) != 1 {
			t.Fatalf("expected one reset notification, got %d", len(fx.passwordNotifier.calls))
		}
	})

	t.Run("reset validates password policy and token", func(t *testing.T) {
		fx := newAuthServiceFixture()
		if err := fx.auth.ResetLocalPassword("token", "weak"); !errors.Is(err, ErrWeakPassword) {
			t.Fatalf("expected ErrWeakPassword, got %v", err)
		}
		if err := fx.auth.ResetLocalPassword("   ", "StrongPass123!"); !errors.Is(err, ErrInvalidVerifyToken) {
			t.Fatalf("expected ErrInvalidVerifyToken for empty token, got %v", err)
		}
	})

	t.Run("reset token not found maps to invalid", func(t *testing.T) {
		fx := newAuthServiceFixture()
		err := fx.auth.ResetLocalPassword("missing", "StrongPass123!")
		if !errors.Is(err, ErrInvalidVerifyToken) {
			t.Fatalf("expected ErrInvalidVerifyToken, got %v", err)
		}
	})

	t.Run("reset consume not found maps to invalid", func(t *testing.T) {
		fx := newAuthServiceFixture()
		uid := fx.seedLocalUser("user@example.com", "User", "StrongPass123!", true)
		raw := "reset-token"
		fx.verifyRepo.seedToken(uid, "password_reset", hashVerificationToken(raw), time.Now().Add(10*time.Minute), false)
		fx.verifyRepo.consumeErr = repository.ErrVerificationTokenNotFound

		err := fx.auth.ResetLocalPassword(raw, "StrongPass123!")
		if !errors.Is(err, ErrInvalidVerifyToken) {
			t.Fatalf("expected ErrInvalidVerifyToken, got %v", err)
		}
	})

	t.Run("reset update password failure", func(t *testing.T) {
		fx := newAuthServiceFixture()
		uid := fx.seedLocalUser("user@example.com", "User", "StrongPass123!", true)
		raw := "reset-token"
		fx.verifyRepo.seedToken(uid, "password_reset", hashVerificationToken(raw), time.Now().Add(10*time.Minute), false)
		fx.localRepo.updatePasswordErr = errors.New("db update failed")

		err := fx.auth.ResetLocalPassword(raw, "StrongPass123!")
		if err == nil || !strings.Contains(err.Error(), "db update failed") {
			t.Fatalf("expected update password failure, got %v", err)
		}
	})

	t.Run("reset revoke all failure", func(t *testing.T) {
		fx := newAuthServiceFixtureWithSessionRepo(&failingRevokeSessionRepo{revokeByUserErr: errors.New("revoke failed")})
		uid := fx.seedLocalUser("user@example.com", "User", "StrongPass123!", true)
		raw := "reset-token"
		fx.verifyRepo.seedToken(uid, "password_reset", hashVerificationToken(raw), time.Now().Add(10*time.Minute), false)

		err := fx.auth.ResetLocalPassword(raw, "StrongPass123!")
		if err == nil || !strings.Contains(err.Error(), "revoke failed") {
			t.Fatalf("expected revoke failure, got %v", err)
		}
	})
}

func TestAuthServiceChangeLocalPasswordMatrix(t *testing.T) {
	t.Run("invalid current credentials", func(t *testing.T) {
		fx := newAuthServiceFixture()
		_, err := fx.auth.LoginWithLocalPassword("missing@example.com", "StrongPass123!", "ua", "127.0.0.1")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("expected ErrInvalidCredentials from missing user login, got %v", err)
		}
	})

	t.Run("wrong current password", func(t *testing.T) {
		fx := newAuthServiceFixture()
		uid := fx.seedLocalUser("user@example.com", "User", "StrongPass123!", true)
		err := fx.auth.ChangeLocalPassword(uid, "WrongPass123!", "EvenStronger123!")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("same password rejected", func(t *testing.T) {
		fx := newAuthServiceFixture()
		uid := fx.seedLocalUser("user@example.com", "User", "StrongPass123!", true)
		err := fx.auth.ChangeLocalPassword(uid, "StrongPass123!", "StrongPass123!")
		if err == nil || !strings.Contains(err.Error(), "must differ") {
			t.Fatalf("expected same password rejection, got %v", err)
		}
	})

	t.Run("success updates password and revokes sessions", func(t *testing.T) {
		fx := newAuthServiceFixture()
		uid := fx.seedLocalUser("user@example.com", "User", "StrongPass123!", true)

		err := fx.auth.ChangeLocalPassword(uid, "StrongPass123!", "EvenStronger123!")
		if err != nil {
			t.Fatalf("change password: %v", err)
		}

		res, err := fx.auth.LoginWithLocalPassword("user@example.com", "EvenStronger123!", "ua", "127.0.0.1")
		if err != nil {
			t.Fatalf("login with new password: %v", err)
		}
		if res.AccessToken == "" {
			t.Fatal("expected login success with new password")
		}
	})
}

func TestAuthServiceGoogleAndParseUserID(t *testing.T) {
	t.Run("google login URL and code disabled gate", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthGoogleEnabled = false

		if got := fx.auth.GoogleLoginURL("state"); got != "" {
			t.Fatalf("expected empty login URL when disabled, got %q", got)
		}
		_, err := fx.auth.LoginWithGoogleCode("code", "ua", "127.0.0.1")
		if !errors.Is(err, ErrGoogleAuthDisabled) {
			t.Fatalf("expected ErrGoogleAuthDisabled, got %v", err)
		}
	})

	t.Run("google code success issues tokens", func(t *testing.T) {
		fx := newAuthServiceFixture()
		fx.cfg.AuthGoogleEnabled = true
		fx.roleRepo.byName["user"] = &domain.Role{ID: 10, Name: "user"}

		res, err := fx.auth.LoginWithGoogleCode("oauth-code", "ua", "127.0.0.1")
		if err != nil {
			t.Fatalf("google login: %v", err)
		}
		if res.User == nil || res.User.Email == "" {
			t.Fatalf("expected user in login result, got %+v", res.User)
		}
		if res.AccessToken == "" || res.RefreshToken == "" || res.CSRFToken == "" {
			t.Fatal("expected issued tokens for google login")
		}
	})

	t.Run("parse user id edge cases", func(t *testing.T) {
		fx := newAuthServiceFixture()
		id, err := fx.auth.ParseUserID("123")
		if err != nil || id != 123 {
			t.Fatalf("expected parsed id 123, got id=%d err=%v", id, err)
		}
		_, err = fx.auth.ParseUserID("not-a-number")
		if err == nil || !strings.Contains(err.Error(), "invalid user subject") {
			t.Fatalf("expected invalid user subject error, got %v", err)
		}
	})
}

func TestAuthServiceAssignBootstrapAdminIfNeededEdgeCases(t *testing.T) {
	fx := newAuthServiceFixture()
	fx.cfg.BootstrapAdminEmail = "admin@example.com"
	fx.roleRepo.byName["admin"] = &domain.Role{ID: 42, Name: "admin"}
	user := fx.seedUser("other@example.com", "Other")

	if err := fx.auth.assignBootstrapAdminIfNeeded(&domain.User{ID: user, Email: "other@example.com"}); err != nil {
		t.Fatalf("expected non-bootstrap user to noop, got %v", err)
	}
	if fx.userRepo.hasRoleByName("other@example.com", "admin") {
		t.Fatal("did not expect admin role assignment for non-bootstrap email")
	}
}

func FuzzAuthServiceParseUserID(f *testing.F) {
	f.Add("123")
	f.Add(" 42 ")
	f.Add("0")
	f.Add("-1")
	f.Add("not-a-number")
	f.Add(strings.Repeat("9", 200))
	f.Add("🔥")

	f.Fuzz(func(t *testing.T, subject string) {
		if len(subject) > 512 {
			subject = subject[:512]
		}
		fx := newAuthServiceFixture()
		id, err := fx.auth.ParseUserID(subject)

		parsed, parseErr := strconv.ParseUint(subject, 10, 64)
		expectSuccess := parseErr == nil

		if expectSuccess {
			if err != nil {
				t.Fatalf("expected success for %q, got err=%v", subject, err)
			}
			if id != uint(parsed) {
				t.Fatalf("id mismatch for %q: got=%d want=%d", subject, id, parsed)
			}
			return
		}

		if err == nil {
			t.Fatalf("expected invalid user subject error for %q, got id=%d", subject, id)
		}
		if !strings.Contains(err.Error(), "invalid user subject") {
			t.Fatalf("expected invalid user subject message for %q, got err=%v", subject, err)
		}
	})
}

func FuzzAuthServiceTokenHandlingRejectsInvalid(f *testing.F) {
	f.Add("", "StrongPass123!")
	f.Add("   ", "StrongPass123!")
	f.Add("missing-token", "StrongPass123!")
	f.Add("🔥token", "StrongPass123!")
	f.Add(strings.Repeat("a", 512), "StrongPass123!")
	f.Add("token", "weak")

	f.Fuzz(func(t *testing.T, token, newPassword string) {
		if len(token) > 1024 {
			token = token[:1024]
		}
		if len(newPassword) > 1024 {
			newPassword = newPassword[:1024]
		}

		fx := newAuthServiceFixture()

		errConfirm := fx.auth.ConfirmLocalEmailVerification(token)
		if strings.TrimSpace(token) == "" {
			if !errors.Is(errConfirm, ErrInvalidVerifyToken) {
				t.Fatalf("confirm expected ErrInvalidVerifyToken for empty token %q, got %v", token, errConfirm)
			}
		} else if errConfirm != nil && !errors.Is(errConfirm, ErrInvalidVerifyToken) {
			t.Fatalf("confirm expected ErrInvalidVerifyToken or nil for token %q, got %v", token, errConfirm)
		}

		errReset := fx.auth.ResetLocalPassword(token, newPassword)
		if errors.Is(errReset, ErrWeakPassword) {
			return
		}
		if !errors.Is(errReset, ErrInvalidVerifyToken) {
			t.Fatalf("reset expected ErrInvalidVerifyToken/ErrWeakPassword for token=%q password_len=%d, got %v", token, len(newPassword), errReset)
		}
	})
}

type authServiceFixture struct {
	cfg              *config.Config
	auth             *AuthService
	userRepo         *userRepoState
	roleRepo         *roleRepoState
	localRepo        *localCredentialState
	verifyRepo       *verificationTokenState
	oauthRepo        *oauthRepoState
	emailNotifier    *emailNotifierState
	passwordNotifier *passwordNotifierState
}

func newAuthServiceFixture() *authServiceFixture {
	return newAuthServiceFixtureWithSessionRepo(newInMemorySessionRepo())
}

func newAuthServiceFixtureWithSessionRepo(sessionRepo repository.SessionRepository) *authServiceFixture {
	cfg := &config.Config{
		AuthLocalEnabled:                  true,
		AuthGoogleEnabled:                 true,
		AuthLocalRequireEmailVerification: false,
		AuthEmailVerifyTokenTTL:           30 * time.Minute,
		AuthPasswordResetTokenTTL:         15 * time.Minute,
		JWTAccessTTL:                      15 * time.Minute,
	}

	userRepo := newUserRepoState()
	roleRepo := newRoleRepoState()
	roleRepo.byName["user"] = &domain.Role{ID: 1, Name: "user"}
	localRepo := newLocalCredentialState(userRepo)
	verifyRepo := newVerificationTokenState()
	oauthRepo := newOAuthRepoState()
	emailNotifier := &emailNotifierState{}
	passwordNotifier := &passwordNotifierState{}
	ctrl := gomock.NewController(tNop{})
	oauthProvider := NewMockOAuthProvider(ctrl)
	oauthProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).AnyTimes().Return(&oauth2.Token{AccessToken: "token"}, nil)
	oauthProvider.EXPECT().FetchUserInfo(gomock.Any(), gomock.Any()).AnyTimes().Return(&OAuthUserInfo{ProviderUserID: "provider-id", Email: "user@example.com", EmailVerified: true}, nil)
	userRepoMock := repogomock.NewMockUserRepository(ctrl)
	roleRepoMock := repogomock.NewMockRoleRepository(ctrl)
	localRepoMock := repogomock.NewMockLocalCredentialRepository(ctrl)
	verifyRepoMock := repogomock.NewMockVerificationTokenRepository(ctrl)
	oauthRepoMock := repogomock.NewMockOAuthRepository(ctrl)
	emailNotifierMock := NewMockEmailVerificationNotifier(ctrl)
	passwordNotifierMock := NewMockPasswordResetNotifier(ctrl)

	userRepoMock.EXPECT().FindByID(gomock.Any()).AnyTimes().DoAndReturn(userRepo.FindByID)
	userRepoMock.EXPECT().FindByEmail(gomock.Any()).AnyTimes().DoAndReturn(userRepo.FindByEmail)
	userRepoMock.EXPECT().Create(gomock.Any()).AnyTimes().DoAndReturn(userRepo.Create)
	userRepoMock.EXPECT().Update(gomock.Any()).AnyTimes().DoAndReturn(userRepo.Update)
	userRepoMock.EXPECT().List().AnyTimes().DoAndReturn(userRepo.List)
	userRepoMock.EXPECT().ListPaged(gomock.Any()).AnyTimes().DoAndReturn(userRepo.ListPaged)
	userRepoMock.EXPECT().SetRoles(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(userRepo.SetRoles)
	userRepoMock.EXPECT().AddRole(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(userRepo.AddRole)

	roleRepoMock.EXPECT().FindByID(gomock.Any()).AnyTimes().DoAndReturn(roleRepo.FindByID)
	roleRepoMock.EXPECT().FindByName(gomock.Any()).AnyTimes().DoAndReturn(roleRepo.FindByName)
	roleRepoMock.EXPECT().List().AnyTimes().Return([]domain.Role{}, nil)
	roleRepoMock.EXPECT().ListPaged(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().Return(repository.PageResult[domain.Role]{}, nil)
	roleRepoMock.EXPECT().Create(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	roleRepoMock.EXPECT().Update(gomock.Any(), gomock.Any()).AnyTimes().Return(nil)
	roleRepoMock.EXPECT().DeleteByID(gomock.Any()).AnyTimes().Return(nil)

	localRepoMock.EXPECT().Create(gomock.Any()).AnyTimes().DoAndReturn(localRepo.Create)
	localRepoMock.EXPECT().FindByUserID(gomock.Any()).AnyTimes().DoAndReturn(localRepo.FindByUserID)
	localRepoMock.EXPECT().FindByEmail(gomock.Any()).AnyTimes().DoAndReturn(localRepo.FindByEmail)
	localRepoMock.EXPECT().UpdatePassword(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(localRepo.UpdatePassword)
	localRepoMock.EXPECT().MarkEmailVerified(gomock.Any()).AnyTimes().DoAndReturn(localRepo.MarkEmailVerified)

	verifyRepoMock.EXPECT().Create(gomock.Any()).AnyTimes().DoAndReturn(verifyRepo.Create)
	verifyRepoMock.EXPECT().InvalidateActiveByUserPurpose(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(verifyRepo.InvalidateActiveByUserPurpose)
	verifyRepoMock.EXPECT().FindActiveByHashPurpose(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(verifyRepo.FindActiveByHashPurpose)
	verifyRepoMock.EXPECT().Consume(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(verifyRepo.Consume)

	oauthRepoMock.EXPECT().FindByProvider(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(oauthRepo.FindByProvider)
	oauthRepoMock.EXPECT().Create(gomock.Any()).AnyTimes().DoAndReturn(oauthRepo.Create)

	emailNotifierMock.EXPECT().SendEmailVerification(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(emailNotifier.SendEmailVerification)
	passwordNotifierMock.EXPECT().SendPasswordReset(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(passwordNotifier.SendPasswordReset)

	oauthSvc := NewOAuthService(oauthProvider, userRepoMock, oauthRepoMock, roleRepoMock)
	tokenSvc := newTestTokenService(sessionRepo)
	userSvc := NewUserService(userRepoMock, NewRBACService())
	authSvc := NewAuthService(cfg, oauthSvc, tokenSvc, userSvc, roleRepoMock, localRepoMock, verifyRepoMock, emailNotifierMock, passwordNotifierMock)

	return &authServiceFixture{
		cfg:              cfg,
		auth:             authSvc,
		userRepo:         userRepo,
		roleRepo:         roleRepo,
		localRepo:        localRepo,
		verifyRepo:       verifyRepo,
		oauthRepo:        oauthRepo,
		emailNotifier:    emailNotifier,
		passwordNotifier: passwordNotifier,
	}
}

type tNop struct{}

func (tNop) Errorf(string, ...any) {}
func (tNop) Fatalf(string, ...any) {}
func (tNop) Helper()               {}

func (fx *authServiceFixture) seedUser(email, name string) uint {
	u := &domain.User{Email: strings.ToLower(strings.TrimSpace(email)), Name: name, Status: "active"}
	if err := fx.userRepo.Create(u); err != nil {
		panic(err)
	}
	return u.ID
}

func (fx *authServiceFixture) seedLocalUser(email, name, password string, verified bool) uint {
	uid := fx.seedUser(email, name)
	hash, err := security.HashPassword(password)
	if err != nil {
		panic(err)
	}
	cred := &domain.LocalCredential{UserID: uid, PasswordHash: hash, EmailVerified: verified}
	if verified {
		now := time.Now().UTC()
		cred.EmailVerifiedAt = &now
	}
	if err := fx.localRepo.Create(cred); err != nil {
		panic(err)
	}
	return uid
}

type userRepoState struct {
	nextID uint
	byID   map[uint]*domain.User
	byMail map[string]uint

	createErr      error
	findByIDErr    error
	findByEmailErr map[string]error
	updateErr      error
	setRolesErr    error
	addRoleErr     error
}

func newUserRepoState() *userRepoState {
	return &userRepoState{
		nextID:         1,
		byID:           map[uint]*domain.User{},
		byMail:         map[string]uint{},
		findByEmailErr: map[string]error{},
	}
}

func (r *userRepoState) FindByID(id uint) (*domain.User, error) {
	if r.findByIDErr != nil {
		return nil, r.findByIDErr
	}
	u, ok := r.byID[id]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	copy := *u
	copy.Roles = append([]domain.Role(nil), u.Roles...)
	return &copy, nil
}

func (r *userRepoState) FindByEmail(email string) (*domain.User, error) {
	normalized := strings.ToLower(strings.TrimSpace(email))
	if err, ok := r.findByEmailErr[normalized]; ok {
		return nil, err
	}
	id, ok := r.byMail[normalized]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	return r.FindByID(id)
}

func (r *userRepoState) Create(user *domain.User) error {
	if r.createErr != nil {
		return r.createErr
	}
	id := r.nextID
	r.nextID++
	copy := *user
	copy.ID = id
	copy.Email = strings.ToLower(strings.TrimSpace(copy.Email))
	r.byID[id] = &copy
	r.byMail[copy.Email] = id
	user.ID = id
	user.Email = copy.Email
	return nil
}

func (r *userRepoState) Update(user *domain.User) error {
	if r.updateErr != nil {
		return r.updateErr
	}
	_, ok := r.byID[user.ID]
	if !ok {
		return gorm.ErrRecordNotFound
	}
	copy := *user
	r.byID[user.ID] = &copy
	r.byMail[copy.Email] = copy.ID
	return nil
}

func (r *userRepoState) List() ([]domain.User, error) {
	out := make([]domain.User, 0, len(r.byID))
	for _, u := range r.byID {
		copy := *u
		copy.Roles = append([]domain.Role(nil), u.Roles...)
		out = append(out, copy)
	}
	return out, nil
}

func (r *userRepoState) ListPaged(query repository.UserListQuery) (repository.PageResult[domain.User], error) {
	users, err := r.List()
	if err != nil {
		return repository.PageResult[domain.User]{}, err
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = len(users)
		if pageSize == 0 {
			pageSize = 1
		}
	}
	page := query.Page
	if page <= 0 {
		page = 1
	}
	return repository.PageResult[domain.User]{
		Items:      users,
		Total:      int64(len(users)),
		Page:       page,
		PageSize:   pageSize,
		TotalPages: 1,
	}, nil
}

func (r *userRepoState) SetRoles(userID uint, roleIDs []uint) error {
	if r.setRolesErr != nil {
		return r.setRolesErr
	}
	u, ok := r.byID[userID]
	if !ok {
		return gorm.ErrRecordNotFound
	}
	roles := make([]domain.Role, 0, len(roleIDs))
	for _, id := range roleIDs {
		roles = append(roles, domain.Role{ID: id, Name: fmt.Sprintf("role-%d", id)})
	}
	u.Roles = roles
	return nil
}

func (r *userRepoState) AddRole(userID, roleID uint) error {
	if r.addRoleErr != nil {
		return r.addRoleErr
	}
	u, ok := r.byID[userID]
	if !ok {
		return gorm.ErrRecordNotFound
	}
	for _, role := range u.Roles {
		if role.ID == roleID {
			return nil
		}
	}
	u.Roles = append(u.Roles, domain.Role{ID: roleID, Name: roleNameFromID(roleID)})
	return nil
}

func (r *userRepoState) hasRoleByName(email, name string) bool {
	u, err := r.FindByEmail(email)
	if err != nil {
		return false
	}
	for _, role := range u.Roles {
		if strings.EqualFold(role.Name, name) {
			return true
		}
	}
	return false
}

func roleNameFromID(id uint) string {
	switch id {
	case 1:
		return "user"
	case 99:
		return "admin"
	default:
		return fmt.Sprintf("role-%d", id)
	}
}

type roleRepoState struct {
	byName        map[string]*domain.Role
	byID          map[uint]*domain.Role
	findByNameErr map[string]error
}

func newRoleRepoState() *roleRepoState {
	return &roleRepoState{
		byName:        map[string]*domain.Role{},
		byID:          map[uint]*domain.Role{},
		findByNameErr: map[string]error{},
	}
}

func (r *roleRepoState) FindByID(id uint) (*domain.Role, error) {
	role, ok := r.byID[id]
	if !ok {
		return nil, repository.ErrRoleNotFound
	}
	copy := *role
	return &copy, nil
}

func (r *roleRepoState) FindByName(name string) (*domain.Role, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	if err, ok := r.findByNameErr[normalized]; ok {
		return nil, err
	}
	role, ok := r.byName[normalized]
	if !ok {
		return nil, repository.ErrRoleNotFound
	}
	copy := *role
	return &copy, nil
}

type localCredentialState struct {
	userRepo *userRepoState
	byUserID map[uint]*domain.LocalCredential

	createErr            error
	updatePasswordErr    error
	markEmailVerifiedErr error
	findByUserIDErr      error
	findByEmailErr       error
}

func newLocalCredentialState(userRepo *userRepoState) *localCredentialState {
	return &localCredentialState{userRepo: userRepo, byUserID: map[uint]*domain.LocalCredential{}}
}

func (r *localCredentialState) Create(credential *domain.LocalCredential) error {
	if r.createErr != nil {
		return r.createErr
	}
	copy := *credential
	r.byUserID[credential.UserID] = &copy
	return nil
}

func (r *localCredentialState) FindByUserID(userID uint) (*domain.LocalCredential, error) {
	if r.findByUserIDErr != nil {
		return nil, r.findByUserIDErr
	}
	cred, ok := r.byUserID[userID]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	copy := *cred
	return &copy, nil
}

func (r *localCredentialState) FindByEmail(email string) (*domain.LocalCredential, error) {
	if r.findByEmailErr != nil {
		return nil, r.findByEmailErr
	}
	u, err := r.userRepo.FindByEmail(email)
	if err != nil {
		return nil, err
	}
	cred, ok := r.byUserID[u.ID]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	copy := *cred
	return &copy, nil
}

func (r *localCredentialState) UpdatePassword(userID uint, newHash string) error {
	if r.updatePasswordErr != nil {
		return r.updatePasswordErr
	}
	cred, ok := r.byUserID[userID]
	if !ok {
		return gorm.ErrRecordNotFound
	}
	cred.PasswordHash = newHash
	return nil
}

func (r *localCredentialState) MarkEmailVerified(userID uint) error {
	if r.markEmailVerifiedErr != nil {
		return r.markEmailVerifiedErr
	}
	cred, ok := r.byUserID[userID]
	if !ok {
		return gorm.ErrRecordNotFound
	}
	now := time.Now().UTC()
	cred.EmailVerified = true
	cred.EmailVerifiedAt = &now
	return nil
}

type verificationTokenState struct {
	nextID uint
	tokens map[uint]*domain.VerificationToken

	invalidateCalls int
	createCalls     int
	consumeCalls    int

	invalidateErr error
	createErr     error
	findErr       error
	consumeErr    error
}

func newVerificationTokenState() *verificationTokenState {
	return &verificationTokenState{nextID: 1, tokens: map[uint]*domain.VerificationToken{}}
}

func (r *verificationTokenState) seedToken(userID uint, purpose, hash string, expiresAt time.Time, used bool) {
	token := &domain.VerificationToken{
		ID:        r.nextID,
		UserID:    userID,
		TokenHash: hash,
		Purpose:   purpose,
		ExpiresAt: expiresAt,
	}
	r.nextID++
	if used {
		now := time.Now().UTC()
		token.UsedAt = &now
	}
	r.tokens[token.ID] = token
}

func (r *verificationTokenState) Create(token *domain.VerificationToken) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.createCalls++
	copy := *token
	copy.ID = r.nextID
	r.nextID++
	r.tokens[copy.ID] = &copy
	token.ID = copy.ID
	return nil
}

func (r *verificationTokenState) InvalidateActiveByUserPurpose(userID uint, purpose string, now time.Time) error {
	if r.invalidateErr != nil {
		return r.invalidateErr
	}
	r.invalidateCalls++
	for _, token := range r.tokens {
		if token.UserID == userID && token.Purpose == purpose && token.UsedAt == nil && token.ExpiresAt.After(now) {
			t := now
			token.UsedAt = &t
		}
	}
	return nil
}

func (r *verificationTokenState) FindActiveByHashPurpose(hash, purpose string, now time.Time) (*domain.VerificationToken, error) {
	if r.findErr != nil {
		return nil, r.findErr
	}
	for _, token := range r.tokens {
		if token.TokenHash == hash && token.Purpose == purpose && token.UsedAt == nil && token.ExpiresAt.After(now) {
			copy := *token
			return &copy, nil
		}
	}
	return nil, repository.ErrVerificationTokenNotFound
}

func (r *verificationTokenState) Consume(tokenID, userID uint, now time.Time) error {
	if r.consumeErr != nil {
		return r.consumeErr
	}
	r.consumeCalls++
	token, ok := r.tokens[tokenID]
	if !ok || token.UserID != userID || token.UsedAt != nil {
		return repository.ErrVerificationTokenNotFound
	}
	t := now
	token.UsedAt = &t
	return nil
}

type emailNotifierState struct {
	calls []VerificationNotification
	err   error
}

func (n *emailNotifierState) SendEmailVerification(ctx context.Context, notification VerificationNotification) error {
	n.calls = append(n.calls, notification)
	return n.err
}

type passwordNotifierState struct {
	calls []PasswordResetNotification
	err   error
}

func (n *passwordNotifierState) SendPasswordReset(ctx context.Context, notification PasswordResetNotification) error {
	n.calls = append(n.calls, notification)
	return n.err
}

type oauthRepoState struct {
	byProviderUser map[string]*domain.OAuthAccount
	createErr      error
	findErr        error
}

func newOAuthRepoState() *oauthRepoState {
	return &oauthRepoState{byProviderUser: map[string]*domain.OAuthAccount{}}
}

func (r *oauthRepoState) FindByProvider(provider, providerUserID string) (*domain.OAuthAccount, error) {
	if r.findErr != nil {
		return nil, r.findErr
	}
	account, ok := r.byProviderUser[provider+"|"+providerUserID]
	if !ok {
		return nil, gorm.ErrRecordNotFound
	}
	copy := *account
	return &copy, nil
}

func (r *oauthRepoState) Create(account *domain.OAuthAccount) error {
	if r.createErr != nil {
		return r.createErr
	}
	copy := *account
	r.byProviderUser[account.Provider+"|"+account.ProviderUserID] = &copy
	return nil
}

type failingRevokeSessionRepo struct {
	revokeByUserErr error
}

func (r *failingRevokeSessionRepo) Create(s *domain.Session) error { return nil }

func (r *failingRevokeSessionRepo) FindByHash(hash string) (*domain.Session, error) {
	return nil, repository.ErrSessionNotFound
}

func (r *failingRevokeSessionRepo) FindActiveByTokenIDForUser(userID uint, tokenID string) (*domain.Session, error) {
	return nil, repository.ErrSessionNotFound
}

func (r *failingRevokeSessionRepo) FindByIDForUser(userID, sessionID uint) (*domain.Session, error) {
	return nil, repository.ErrSessionNotFound
}

func (r *failingRevokeSessionRepo) ListActiveByUserID(userID uint) ([]domain.Session, error) {
	return nil, nil
}

func (r *failingRevokeSessionRepo) RotateSession(oldHash string, newSession *domain.Session) (*domain.Session, error) {
	return nil, repository.ErrSessionNotFound
}

func (r *failingRevokeSessionRepo) UpdateTokenLineageByHash(hash, tokenID, familyID string) error {
	return nil
}

func (r *failingRevokeSessionRepo) MarkReuseDetectedByHash(hash string) error { return nil }

func (r *failingRevokeSessionRepo) RevokeByHash(hash, reason string) error { return nil }

func (r *failingRevokeSessionRepo) RevokeByIDForUser(userID, sessionID uint, reason string) (bool, error) {
	return false, nil
}

func (r *failingRevokeSessionRepo) RevokeOthersByUser(userID, keepSessionID uint, reason string) (int64, error) {
	return 0, nil
}

func (r *failingRevokeSessionRepo) RevokeByFamilyID(familyID, reason string) (int64, error) {
	return 0, nil
}

func (r *failingRevokeSessionRepo) RevokeByUserID(userID uint, reason string) error {
	return r.revokeByUserErr
}

func (r *failingRevokeSessionRepo) CleanupExpired() (int64, error) { return 0, nil }
