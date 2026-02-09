package integration

import (
	"net/http"
	"testing"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
)

func TestEmailVerificationRegisterRequestConfirmAndLogin(t *testing.T) {
	notifier := &verificationCaptureNotifier{}
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.AuthLocalRequireEmailVerification = true
		},
		verifyNotifier: notifier,
		resetNotifier:  notifier,
	})
	defer closeFn()

	registerBody := map[string]string{
		"email":    "verify-flow@example.com",
		"name":     "Verify Flow",
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
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected unverified login blocked, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "EMAIL_UNVERIFIED" {
		t.Fatalf("expected EMAIL_UNVERIFIED, got %#v", env.Error)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/verify/request", map[string]string{
		"email": registerBody["email"],
	}, nil)
	if resp.StatusCode != http.StatusAccepted || !env.Success {
		t.Fatalf("verify request failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	token := notifier.LastToken()
	if token == "" {
		t.Fatal("expected verification token to be captured")
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/verify/confirm", map[string]string{
		"token": token,
	}, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("verify confirm failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/login", map[string]string{
		"email":    registerBody["email"],
		"password": registerBody["password"],
	}, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("verified login failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
}

func TestEmailVerificationExpiredTokenFails(t *testing.T) {
	notifier := &verificationCaptureNotifier{}
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.AuthLocalRequireEmailVerification = true
			cfg.AuthEmailVerifyTokenTTL = -1
		},
		verifyNotifier: notifier,
		resetNotifier:  notifier,
	})
	defer closeFn()

	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/register", map[string]string{
		"email":    "expired-verify@example.com",
		"name":     "Expired Verify",
		"password": "Valid#Pass1234",
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("register failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/verify/request", map[string]string{
		"email": "expired-verify@example.com",
	}, nil)
	if resp.StatusCode != http.StatusAccepted || !env.Success {
		t.Fatalf("verify request failed: status=%d", resp.StatusCode)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/verify/confirm", map[string]string{
		"token": notifier.LastToken(),
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected expired token 400, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "INVALID_OR_EXPIRED_TOKEN" {
		t.Fatalf("expected INVALID_OR_EXPIRED_TOKEN, got %#v", env.Error)
	}
}

func TestEmailVerificationReuseAndInvalidTokenFailUniformly(t *testing.T) {
	notifier := &verificationCaptureNotifier{}
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.AuthLocalRequireEmailVerification = true
		},
		verifyNotifier: notifier,
		resetNotifier:  notifier,
	})
	defer closeFn()

	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/register", map[string]string{
		"email":    "reuse-verify@example.com",
		"name":     "Reuse Verify",
		"password": "Valid#Pass1234",
	}, nil)
	if resp.StatusCode != http.StatusCreated || !env.Success {
		t.Fatalf("register failed: status=%d success=%v", resp.StatusCode, env.Success)
	}
	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/verify/request", map[string]string{
		"email": "reuse-verify@example.com",
	}, nil)
	if resp.StatusCode != http.StatusAccepted || !env.Success {
		t.Fatalf("verify request failed: status=%d success=%v", resp.StatusCode, env.Success)
	}

	token := notifier.LastToken()
	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/verify/confirm", map[string]string{
		"token": token,
	}, nil)
	if resp.StatusCode != http.StatusOK || !env.Success {
		t.Fatalf("first confirm expected success, got %d", resp.StatusCode)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/verify/confirm", map[string]string{
		"token": token,
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("reuse expected 400, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "INVALID_OR_EXPIRED_TOKEN" {
		t.Fatalf("expected INVALID_OR_EXPIRED_TOKEN on reuse, got %#v", env.Error)
	}

	resp, env = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/verify/confirm", map[string]string{
		"token": "invalid-token",
	}, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid token expected 400, got %d", resp.StatusCode)
	}
	if env.Error == nil || env.Error.Code != "INVALID_OR_EXPIRED_TOKEN" {
		t.Fatalf("expected INVALID_OR_EXPIRED_TOKEN on invalid token, got %#v", env.Error)
	}
}

func TestEmailVerificationRequestUnknownEmailReturnsAccepted(t *testing.T) {
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.AuthLocalRequireEmailVerification = true
		},
	})
	defer closeFn()

	resp, env := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/verify/request", map[string]string{
		"email": "unknown@example.com",
	}, nil)
	if resp.StatusCode != http.StatusAccepted || !env.Success {
		t.Fatalf("unknown email should still return accepted, got status=%d success=%v", resp.StatusCode, env.Success)
	}
}
