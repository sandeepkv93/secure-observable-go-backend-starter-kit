package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type testOAuthProvider struct {
	exchangeFn func(ctx context.Context, code string) (*oauth2.Token, error)
	userinfoFn func(ctx context.Context, token *oauth2.Token) (*OAuthUserInfo, error)
}

func (p testOAuthProvider) AuthCodeURL(_ string) string { return "" }

func (p testOAuthProvider) Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	if p.exchangeFn != nil {
		return p.exchangeFn(ctx, code)
	}
	return &oauth2.Token{AccessToken: "token"}, nil
}

func (p testOAuthProvider) FetchUserInfo(ctx context.Context, token *oauth2.Token) (*OAuthUserInfo, error) {
	if p.userinfoFn != nil {
		return p.userinfoFn(ctx, token)
	}
	return &OAuthUserInfo{ProviderUserID: "provider-id", Email: "user@example.com", EmailVerified: true}, nil
}

func TestOAuthServiceHandleGoogleCallbackExchangeError(t *testing.T) {
	svc := NewOAuthService(
		testOAuthProvider{exchangeFn: func(context.Context, string) (*oauth2.Token, error) {
			return nil, context.DeadlineExceeded
		}},
		nil,
		nil,
		nil,
	)

	_, err := svc.HandleGoogleCallback(context.Background(), "code")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestOAuthServiceHandleGoogleCallbackUserInfoError(t *testing.T) {
	userinfoErr := errors.New("userinfo status: 500")
	svc := NewOAuthService(
		testOAuthProvider{userinfoFn: func(context.Context, *oauth2.Token) (*OAuthUserInfo, error) {
			return nil, userinfoErr
		}},
		nil,
		nil,
		nil,
	)

	_, err := svc.HandleGoogleCallback(context.Background(), "code")
	if !errors.Is(err, userinfoErr) {
		t.Fatalf("expected userinfo error, got %v", err)
	}
}

func TestOAuthServiceHandleGoogleCallbackEmailNotVerified(t *testing.T) {
	svc := NewOAuthService(
		testOAuthProvider{userinfoFn: func(context.Context, *oauth2.Token) (*OAuthUserInfo, error) {
			return &OAuthUserInfo{ProviderUserID: "provider-id", Email: "user@example.com", EmailVerified: false}, nil
		}},
		nil,
		nil,
		nil,
	)

	_, err := svc.HandleGoogleCallback(context.Background(), "code")
	if err == nil || err.Error() != "google email not verified" {
		t.Fatalf("expected google email not verified error, got %v", err)
	}
}

func TestOAuthServiceHandleGoogleCallbackNilUserInfo(t *testing.T) {
	svc := NewOAuthService(
		testOAuthProvider{
			userinfoFn: func(context.Context, *oauth2.Token) (*OAuthUserInfo, error) {
				return nil, nil
			},
		},
		nil,
		nil,
		nil,
	)

	_, err := svc.HandleGoogleCallback(context.Background(), "code")
	if err == nil || err.Error() != "missing required userinfo fields" {
		t.Fatalf("expected missing required userinfo fields error, got %v", err)
	}
}

func TestClassifyOAuthError(t *testing.T) {
	if got := classifyOAuthError(context.Canceled); got != "context_canceled" {
		t.Fatalf("expected context_canceled, got %q", got)
	}
	if got := classifyOAuthError(context.DeadlineExceeded); got != "timeout" {
		t.Fatalf("expected timeout, got %q", got)
	}
	if got := classifyOAuthError(errors.New("userinfo status: 401")); got != "userinfo_status" {
		t.Fatalf("expected userinfo_status, got %q", got)
	}
	if got := classifyOAuthError(errors.New("missing required userinfo fields")); got != "invalid_userinfo" {
		t.Fatalf("expected invalid_userinfo, got %q", got)
	}
	if got := classifyOAuthError(errors.New("oauth2: cannot fetch token")); got != "oauth2_exchange" {
		t.Fatalf("expected oauth2_exchange, got %q", got)
	}
}

func FuzzClassifyOAuthErrorRobustness(f *testing.F) {
	f.Add(uint8(0), "")
	f.Add(uint8(1), "userinfo status: 500")
	f.Add(uint8(2), "missing required userinfo fields")
	f.Add(uint8(3), "oauth2: invalid grant")
	f.Add(uint8(4), "random 🔥 text")

	f.Fuzz(func(t *testing.T, kind uint8, msg string) {
		if len(msg) > 2048 {
			msg = msg[:2048]
		}

		var err error
		switch kind % 6 {
		case 0:
			err = nil
		case 1:
			err = context.Canceled
		case 2:
			err = context.DeadlineExceeded
		case 3:
			err = timeoutNetErr{msg: msg}
		case 4:
			err = errors.New(msg)
		default:
			err = fmt.Errorf("wrapped: %w", errors.New(msg))
		}

		got := classifyOAuthError(err)
		switch got {
		case "none", "context_canceled", "timeout", "userinfo_status", "invalid_userinfo", "oauth2_exchange", "other":
		default:
			t.Fatalf("unexpected classification %q for err=%v", got, err)
		}

		if err == nil && got != "none" {
			t.Fatalf("nil error should classify to none, got %q", got)
		}
		if strings.Contains(strings.ToLower(msg), "userinfo status:") && err != nil && got == "other" {
			t.Fatalf("userinfo status message should not classify as other: %q", got)
		}
	})
}

type timeoutNetErr struct {
	msg string
}

func (e timeoutNetErr) Error() string   { return e.msg }
func (e timeoutNetErr) Timeout() bool   { return true }
func (e timeoutNetErr) Temporary() bool { return true }
