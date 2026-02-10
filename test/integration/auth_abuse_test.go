package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/config"
)

func TestLocalLoginAbuseCooldownBlocksRapidRetries(t *testing.T) {
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.AuthAbuseFreeAttempts = 0
			cfg.AuthAbuseBaseDelay = time.Second
			cfg.AuthAbuseMultiplier = 2
			cfg.AuthAbuseMaxDelay = 2 * time.Second
			cfg.AuthAbuseResetWindow = 10 * time.Minute
		},
	})
	defer closeFn()

	registerAndLogin(t, client, baseURL, "abuse-login@example.com", "Valid#Pass1234")

	// clear valid auth cookies to avoid session-auth effects on the login endpoint behavior
	resp, _ := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/logout", nil, map[string]string{
		"X-CSRF-Token": cookieValue(t, client, baseURL, "csrf_token"),
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logout setup failed: %d", resp.StatusCode)
	}

	resp, _ = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/login", map[string]string{
		"email":    "abuse-login@example.com",
		"password": "wrong-password",
	}, map[string]string{
		"X-Forwarded-For": "10.1.1.1",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected failed login 401, got %d", resp.StatusCode)
	}

	resp, _ = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/login", map[string]string{
		"email":    "abuse-login@example.com",
		"password": "Valid#Pass1234",
	}, map[string]string{
		"X-Forwarded-For": "10.1.1.1",
	})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected cooldown block 429, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Retry-After"); got == "" {
		t.Fatal("expected Retry-After header on abuse cooldown")
	}

	time.Sleep(1100 * time.Millisecond)

	resp, _ = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/login", map[string]string{
		"email":    "abuse-login@example.com",
		"password": "Valid#Pass1234",
	}, map[string]string{
		"X-Forwarded-For": "10.1.1.1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected login success after cooldown, got %d", resp.StatusCode)
	}
}

func TestPasswordForgotAbuseCooldownUsesIdentityAndIP(t *testing.T) {
	baseURL, client, closeFn := newAuthTestServerWithOptions(t, authTestServerOptions{
		cfgOverride: func(cfg *config.Config) {
			cfg.AuthAbuseFreeAttempts = 0
			cfg.AuthAbuseBaseDelay = time.Second
			cfg.AuthAbuseMultiplier = 2
			cfg.AuthAbuseMaxDelay = 2 * time.Second
			cfg.AuthAbuseResetWindow = 10 * time.Minute
		},
	})
	defer closeFn()

	registerOnly(t, client, baseURL, "abuse-forgot@example.com")

	resp, _ := doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/forgot", map[string]string{
		"email": "abuse-forgot@example.com",
	}, map[string]string{
		"X-Forwarded-For": "11.0.0.1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected first forgot request 200, got %d", resp.StatusCode)
	}

	resp, _ = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/forgot", map[string]string{
		"email": "abuse-forgot@example.com",
	}, map[string]string{
		"X-Forwarded-For": "11.0.0.9",
	})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected identity cooldown block 429, got %d", resp.StatusCode)
	}

	resp, _ = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/forgot", map[string]string{
		"email": "different@example.com",
	}, map[string]string{
		"X-Forwarded-For": "11.0.0.1",
	})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected ip cooldown block 429, got %d", resp.StatusCode)
	}

	time.Sleep(1100 * time.Millisecond)

	resp, _ = doJSON(t, client, http.MethodPost, baseURL+"/api/v1/auth/local/password/forgot", map[string]string{
		"email": "different@example.com",
	}, map[string]string{
		"X-Forwarded-For": "11.0.0.2",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected forgot request to recover after cooldown, got %d", resp.StatusCode)
	}
}
