package security

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewCookieManagerSameSiteMapping(t *testing.T) {
	if got := NewCookieManager("", true, "strict").SameSite; got != http.SameSiteStrictMode {
		t.Fatalf("strict mapping mismatch: %v", got)
	}
	if got := NewCookieManager("", true, "none").SameSite; got != http.SameSiteNoneMode {
		t.Fatalf("none mapping mismatch: %v", got)
	}
	if got := NewCookieManager("", true, "unexpected").SameSite; got != http.SameSiteLaxMode {
		t.Fatalf("default mapping mismatch: %v", got)
	}
}

func TestCookieManagerSetTokenCookiesFlagsAndPaths(t *testing.T) {
	mgr := NewCookieManager("example.com", true, "strict")
	rr := httptest.NewRecorder()
	mgr.SetTokenCookies(rr, "a", "r", "c", 2*time.Hour)

	res := rr.Result()
	cookies := res.Cookies()
	if len(cookies) != 3 {
		t.Fatalf("expected 3 cookies, got %d", len(cookies))
	}

	byName := map[string]*http.Cookie{}
	for _, c := range cookies {
		byName[c.Name] = c
	}

	access := byName["access_token"]
	if access == nil || access.Path != "/" || !access.HttpOnly || !access.Secure || access.Domain != "example.com" || access.MaxAge != 900 {
		t.Fatalf("unexpected access cookie: %#v", access)
	}
	if access.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected access same-site: %v", access.SameSite)
	}

	refresh := byName["refresh_token"]
	if refresh == nil || refresh.Path != "/api/v1/auth" || !refresh.HttpOnly || refresh.MaxAge != int((2*time.Hour).Seconds()) {
		t.Fatalf("unexpected refresh cookie: %#v", refresh)
	}

	csrf := byName["csrf_token"]
	if csrf == nil || csrf.Path != "/" || csrf.HttpOnly || csrf.MaxAge != int((2*time.Hour).Seconds()) {
		t.Fatalf("unexpected csrf cookie: %#v", csrf)
	}
}

func TestCookieManagerClearTokenCookies(t *testing.T) {
	mgr := NewCookieManager("example.com", false, "lax")
	rr := httptest.NewRecorder()
	mgr.ClearTokenCookies(rr)

	res := rr.Result()
	cookies := res.Cookies()
	if len(cookies) != 4 {
		t.Fatalf("expected 4 cleared cookies, got %d", len(cookies))
	}

	expect := map[string]struct {
		path     string
		httpOnly bool
	}{
		"access_token":  {path: "/", httpOnly: true},
		"refresh_token": {path: "/api/v1/auth", httpOnly: true},
		"csrf_token":    {path: "/", httpOnly: false},
		"oauth_state":   {path: "/api/v1/auth/google", httpOnly: true},
	}

	for _, c := range cookies {
		want, ok := expect[c.Name]
		if !ok {
			t.Fatalf("unexpected cleared cookie %q", c.Name)
		}
		if c.MaxAge != -1 || c.Value != "" {
			t.Fatalf("cookie %q expected cleared value/max-age, got value=%q max_age=%d", c.Name, c.Value, c.MaxAge)
		}
		if c.Path != want.path || c.HttpOnly != want.httpOnly {
			t.Fatalf("cookie %q path/httpOnly mismatch: got path=%s httpOnly=%v", c.Name, c.Path, c.HttpOnly)
		}
	}
}

func TestGetCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "x"})

	if got := GetCookie(req, "csrf_token"); got != "x" {
		t.Fatalf("unexpected cookie value %q", got)
	}
	if got := GetCookie(req, "missing"); got != "" {
		t.Fatalf("expected empty cookie value for missing cookie, got %q", got)
	}
}
