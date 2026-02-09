package integration

import (
	"net/http"
	"testing"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
)

func TestPasswordResetHappyPathRevokesSessions(t *testing.T) {
	notifier := &verificationCaptureNotifier{}
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		verifyNotifier: notifier,
		resetNotifier:  notifier,
	})
	defer closeFn()

	registerBody := map[string]string{
		"email":    "password-reset@example.com",
		"name":     "Reset User",
		"password": "Valid#Pass1234",
	}
	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/register", registerBody, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("register failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/login", map[string]string{
		"email":    registerBody["email"],
		"password": registerBody["password"],
	}, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("login failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	oldRefresh := cookieValue(t, client, baseURL, "refresh_token")
	oldCSRF := cookieValue(t, client, baseURL, "csrf_token")

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/forgot", map[string]string{
		"email": registerBody["email"],
	}, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("forgot failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	token := notifier.LastResetToken()
	if token == "" {
		t.Fatal("expected reset token")
	}
	newPassword := "New#ValidPass1234"
	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/reset", map[string]string{
		"token":        token,
		"new_password": newPassword,
	}, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("reset failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/login", map[string]string{
		"email":    registerBody["email"],
		"password": registerBody["password"],
	}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old password should fail after reset, got %d", resp.StatusCode)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/login", map[string]string{
		"email":    registerBody["email"],
		"password": newPassword,
	}, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("new password login failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	resp, _ = doRaw(t, client, http.MethodPost, baseURL+"/api/v1/auth/refresh", nil, map[string]string{
		"X-CSRF-Token": oldCSRF,
	}, []*http.Cookie{
		{Name: "refresh_token", Value: oldRefresh, Path: "/api/v1/auth"},
		{Name: "csrf_token", Value: oldCSRF, Path: "/"},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old refresh should be revoked after password reset, got %d", resp.StatusCode)
	}
}

func TestPasswordResetReuseAndExpiredFail(t *testing.T) {
	notifier := &verificationCaptureNotifier{}
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.AuthPasswordResetTokenTTL = -1
		},
		verifyNotifier: notifier,
		resetNotifier:  notifier,
	})
	defer closeFn()

	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/register", map[string]string{
		"email":    "password-reset-expired@example.com",
		"name":     "Reset Expired",
		"password": "Valid#Pass1234",
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("register failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/forgot", map[string]string{
		"email": "password-reset-expired@example.com",
	}, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("forgot failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/reset", map[string]string{
		"token":        notifier.LastResetToken(),
		"new_password": "New#ValidPass1234",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expired token expected 400, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "INVALID_OR_EXPIRED_TOKEN" {
		t.Fatalf("expected INVALID_OR_EXPIRED_TOKEN, got %#v", env.Error)
	}
}

func TestPasswordResetReplayAndUnknownForgotResponse(t *testing.T) {
	notifier := &verificationCaptureNotifier{}
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		verifyNotifier: notifier,
		resetNotifier:  notifier,
	})
	defer closeFn()

	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/register", map[string]string{
		"email":    "password-reset-replay@example.com",
		"name":     "Reset Replay",
		"password": "Valid#Pass1234",
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("register failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/forgot", map[string]string{
		"email": "password-reset-replay@example.com",
	}, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("forgot failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	token := notifier.LastResetToken()

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/reset", map[string]string{
		"token":        token,
		"new_password": "New#ValidPass1234",
	}, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("first reset should pass: status=%d success=%v", resp.StatusCode, env.Success)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/reset", map[string]string{
		"token":        token,
		"new_password": "Other#ValidPass1234",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay should fail 400, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "INVALID_OR_EXPIRED_TOKEN" {
		t.Fatalf("expected INVALID_OR_EXPIRED_TOKEN, got %#v", env.Error)
	}

	respKnown, envKnown := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/forgot", map[string]string{
		"email": "password-reset-replay@example.com",
	}, nil)
	respUnknown, envUnknown := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/forgot", map[string]string{
		"email": "no-user@example.com",
	}, nil)
	if respKnown.StatusCode != http.StatusOK || respUnknown.StatusCode != http.StatusOK {
		t.Fatalf("forgot responses should be indistinguishable: known=%d unknown=%d", respKnown.StatusCode, respUnknown.StatusCode)
	}
	if !envKnown.Success || !envUnknown.Success {
		t.Fatalf("forgot responses should both be successful: known=%v unknown=%v", envKnown.Success, envUnknown.Success)
	}
}
