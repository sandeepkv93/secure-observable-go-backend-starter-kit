package middleware

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/service"
	servicegomock "github.com/sandeepkv93/everything-backend-starter-kit/internal/service/gomock"
	"go.uber.org/mock/gomock"
)

type beginCall struct {
	scope       string
	key         string
	fingerprint string
	ttl         time.Duration
}

type completeCall struct {
	scope       string
	key         string
	fingerprint string
	response    service.CachedHTTPResponse
	ttl         time.Duration
}

type idempotencyStoreConfig struct {
	beginResult service.IdempotencyBeginResult
	beginErr    error
	completeErr error
}

func newIdempotencyStoreMock(t *testing.T, cfg idempotencyStoreConfig) (*servicegomock.MockIdempotencyStore, *[]beginCall, *[]completeCall) {
	t.Helper()

	ctrl := gomock.NewController(t)
	store := servicegomock.NewMockIdempotencyStore(ctrl)
	beginCalls := []beginCall{}
	completeCalls := []completeCall{}

	store.EXPECT().Begin(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, scope, key, fingerprint string, ttl time.Duration) (service.IdempotencyBeginResult, error) {
			beginCalls = append(beginCalls, beginCall{scope: scope, key: key, fingerprint: fingerprint, ttl: ttl})
			if cfg.beginErr != nil {
				return service.IdempotencyBeginResult{}, cfg.beginErr
			}
			return cfg.beginResult, nil
		},
	)
	store.EXPECT().Complete(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, scope, key, fingerprint string, response service.CachedHTTPResponse, ttl time.Duration) error {
			completeCalls = append(completeCalls, completeCall{
				scope:       scope,
				key:         key,
				fingerprint: fingerprint,
				response:    response,
				ttl:         ttl,
			})
			return cfg.completeErr
		},
	)

	return store, &beginCalls, &completeCalls
}

type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func (errReadCloser) Close() error { return nil }

func TestIdempotencyMiddlewareRejectsMissingAndTooLongKey(t *testing.T) {
	tests := []struct {
		name string
		key  string
	}{
		{name: "missing key", key: ""},
		{name: "too long key", key: strings.Repeat("a", 129)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, beginCalls, _ := newIdempotencyStoreMock(t, idempotencyStoreConfig{})
			mw := NewIdempotencyMiddleware(store, time.Minute)
			h := mw.Middleware("register")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			}))

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(`{"email":"u@example.com"}`))
			if tc.key != "" {
				req.Header.Set(idempotencyHeader, tc.key)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", rr.Code)
			}
			if len(*beginCalls) != 0 {
				t.Fatalf("expected no begin calls, got %d", len(*beginCalls))
			}
		})
	}
}

func TestIdempotencyMiddlewareRejectsUnreadableBody(t *testing.T) {
	store, beginCalls, _ := newIdempotencyStoreMock(t, idempotencyStoreConfig{})
	mw := NewIdempotencyMiddleware(store, time.Minute)
	h := mw.Middleware("register")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", io.NopCloser(strings.NewReader("ignored")))
	req.Body = errReadCloser{}
	req.Header.Set(idempotencyHeader, "req-1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if len(*beginCalls) != 0 {
		t.Fatalf("expected no begin calls on body read error, got %d", len(*beginCalls))
	}
}

func TestIdempotencyMiddlewareBeginErrorReturnsInternal(t *testing.T) {
	store, beginCalls, completeCalls := newIdempotencyStoreMock(t, idempotencyStoreConfig{beginErr: errors.New("redis unavailable")})
	mw := NewIdempotencyMiddleware(store, 2*time.Minute)
	h := mw.Middleware("register")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(`{"x":1}`))
	req.Header.Set(idempotencyHeader, "req-2")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	if len(*beginCalls) != 1 {
		t.Fatalf("expected one begin call, got %d", len(*beginCalls))
	}
	if len(*completeCalls) != 0 {
		t.Fatalf("expected no complete calls when begin fails, got %d", len(*completeCalls))
	}
}

func TestIdempotencyMiddlewareBeginStateBranches(t *testing.T) {
	tests := []struct {
		name       string
		beginState service.IdempotencyState
		cached     *service.CachedHTTPResponse
		wantCode   int
		wantReplay bool
	}{
		{name: "in progress", beginState: service.IdempotencyStateInProgress, wantCode: http.StatusConflict},
		{name: "conflict", beginState: service.IdempotencyStateConflict, wantCode: http.StatusConflict},
		{
			name:       "replay cached response",
			beginState: service.IdempotencyStateReplay,
			cached: &service.CachedHTTPResponse{
				StatusCode:  http.StatusAccepted,
				ContentType: "application/problem+json",
				Body:        []byte(`{"message":"cached"}`),
			},
			wantCode:   http.StatusAccepted,
			wantReplay: true,
		},
		{name: "replay nil cached", beginState: service.IdempotencyStateReplay, wantCode: http.StatusNoContent, wantReplay: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, _, completeCalls := newIdempotencyStoreMock(t, idempotencyStoreConfig{beginResult: service.IdempotencyBeginResult{State: tc.beginState, Cached: tc.cached}})
			mw := NewIdempotencyMiddleware(store, time.Minute)
			h := mw.Middleware("register")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
			}))

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(`{"x":1}`))
			req.Header.Set(idempotencyHeader, "req-3")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tc.wantCode {
				t.Fatalf("expected %d, got %d", tc.wantCode, rr.Code)
			}
			if tc.wantReplay {
				if got := rr.Header().Get("X-Idempotency-Replayed"); got != "true" {
					t.Fatalf("expected replay header true, got %q", got)
				}
				if got := rr.Header().Get("Content-Type"); got != tc.cached.ContentType {
					t.Fatalf("expected content-type %q, got %q", tc.cached.ContentType, got)
				}
				if body := rr.Body.String(); body != string(tc.cached.Body) {
					t.Fatalf("expected cached body %q, got %q", string(tc.cached.Body), body)
				}
			} else if got := rr.Header().Get("X-Idempotency-Replayed"); got != "" {
				t.Fatalf("expected no replay header, got %q", got)
			}
			if len(*completeCalls) != 0 {
				t.Fatalf("expected no complete calls for begin state %s, got %d", tc.beginState, len(*completeCalls))
			}
		})
	}
}

func TestIdempotencyMiddlewareCompleteBehavior(t *testing.T) {
	t.Run("downstream 5xx does not persist complete", func(t *testing.T) {
		store, _, completeCalls := newIdempotencyStoreMock(t, idempotencyStoreConfig{beginResult: service.IdempotencyBeginResult{State: service.IdempotencyStateNew}})
		mw := NewIdempotencyMiddleware(store, time.Minute)
		h := mw.Middleware("register")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "downstream failed", http.StatusInternalServerError)
		}))

		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(`{"x":1}`))
		req.Header.Set(idempotencyHeader, "req-5")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500, got %d", rr.Code)
		}
		if len(*completeCalls) != 0 {
			t.Fatalf("expected no complete calls for 5xx response, got %d", len(*completeCalls))
		}
	})

	t.Run("complete store failure does not fail response", func(t *testing.T) {
		store, _, completeCalls := newIdempotencyStoreMock(t, idempotencyStoreConfig{beginResult: service.IdempotencyBeginResult{State: service.IdempotencyStateNew}, completeErr: errors.New("complete failed")})
		mw := NewIdempotencyMiddleware(store, 2*time.Minute)
		h := mw.Middleware("register")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))

		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(`{"x":1}`))
		req.Header.Set(idempotencyHeader, "req-6")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("expected original 201 response, got %d", rr.Code)
		}
		if rr.Body.String() != `{"ok":true}` {
			t.Fatalf("expected original response body, got %q", rr.Body.String())
		}
		if len(*completeCalls) != 1 {
			t.Fatalf("expected one complete call, got %d", len(*completeCalls))
		}
		cc := (*completeCalls)[0]
		if cc.response.StatusCode != http.StatusCreated {
			t.Fatalf("expected cached status 201, got %d", cc.response.StatusCode)
		}
		if cc.response.ContentType != "application/json" {
			t.Fatalf("expected cached content-type application/json, got %q", cc.response.ContentType)
		}
	})
}

func TestIdempotencyFingerprintUsesRoutePatternAndActorIdentity(t *testing.T) {
	t.Run("route pattern preferred over raw path", func(t *testing.T) {
		req1 := httptest.NewRequest(http.MethodPost, "/orders/1", strings.NewReader(`{"item":"book"}`))
		req1.RemoteAddr = "198.51.100.9:1111"
		req2 := httptest.NewRequest(http.MethodPost, "/orders/2", strings.NewReader(`{"item":"book"}`))
		req2.RemoteAddr = "198.51.100.9:1111"

		routeCtx1 := chi.NewRouteContext()
		routeCtx1.RoutePatterns = []string{"/orders/{orderID}"}
		req1 = req1.WithContext(context.WithValue(req1.Context(), chi.RouteCtxKey, routeCtx1))

		routeCtx2 := chi.NewRouteContext()
		routeCtx2.RoutePatterns = []string{"/orders/{orderID}"}
		req2 = req2.WithContext(context.WithValue(req2.Context(), chi.RouteCtxKey, routeCtx2))

		f1 := fingerprintRequest(req1, "register", []byte(`{"item":"book"}`))
		f2 := fingerprintRequest(req2, "register", []byte(`{"item":"book"}`))
		if f1 != f2 {
			t.Fatalf("expected same fingerprint for same route pattern/body/actor, got %q vs %q", f1, f2)
		}
	})

	t.Run("actor derivation uses claims subject then IP", func(t *testing.T) {
		base := httptest.NewRequest(http.MethodPost, "/orders/5", strings.NewReader(`{"item":"book"}`))
		base.RemoteAddr = "203.0.113.9:8080"
		base.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.9")

		routeCtx := chi.NewRouteContext()
		routeCtx.RoutePatterns = []string{"/orders/{orderID}"}
		ctxWithRoute := context.WithValue(base.Context(), chi.RouteCtxKey, routeCtx)

		claims := &security.Claims{}
		claims.Subject = "42"
		withClaims := base.WithContext(context.WithValue(ctxWithRoute, ClaimsContextKey, claims))
		withoutClaims := base.WithContext(ctxWithRoute)

		f1 := fingerprintRequest(withClaims, "register", []byte(`{"item":"book"}`))
		f2 := fingerprintRequest(withoutClaims, "register", []byte(`{"item":"book"}`))
		if f1 == f2 {
			t.Fatalf("expected different fingerprints for subject actor vs IP actor, got %q", f1)
		}
		if got := actorForScope(withClaims); got != "sub:42" {
			t.Fatalf("expected claims actor sub:42, got %q", got)
		}
		if got := actorForScope(withoutClaims); got != "ip:198.51.100.7" {
			t.Fatalf("expected xff-derived ip actor, got %q", got)
		}
	})
}

func FuzzIdempotencyMiddlewareKeyAndBodyRobustness(f *testing.F) {
	f.Add(true, "idem-key-1", "/api/v1/auth/register", "POST", "register", []byte(`{"email":"u@example.com"}`), "", "", "", false)
	f.Add(false, "", "/api/v1/auth/register", "POST", "register", []byte(`{}`), "", "", "", false)
	f.Add(true, strings.Repeat("k", 129), "/api/v1/auth/register", "POST", "register", []byte(`{}`), "", "", "", false)
	f.Add(true, "idem-key-unicode-🔥", "/api/v1/orders/42", "PUT", "orders", []byte(strings.Repeat("a", 512)), "/api/v1/orders/{id}", "42", "198.51.100.10, 203.0.113.1", true)

	f.Fuzz(func(t *testing.T, includeKey bool, key, path, method, scope string, body []byte, routePattern, subject, xff string, withClaims bool) {
		if len(key) > 512 {
			key = key[:512]
		}
		if len(path) > 1024 {
			path = path[:1024]
		}
		if len(method) > 32 {
			method = method[:32]
		}
		if len(scope) > 128 {
			scope = scope[:128]
		}
		if len(routePattern) > 256 {
			routePattern = routePattern[:256]
		}
		if len(subject) > 128 {
			subject = subject[:128]
		}
		if len(xff) > 256 {
			xff = xff[:256]
		}
		if len(body) > 4096 {
			body = body[:4096]
		}

		if scope == "" {
			scope = "fuzz_scope"
		}
		if method == "" {
			method = http.MethodPost
		}
		method = sanitizeFuzzMethod(method)
		path = sanitizeFuzzPath(path)

		store, beginCalls, completeCalls := newIdempotencyStoreMock(t, idempotencyStoreConfig{beginResult: service.IdempotencyBeginResult{State: service.IdempotencyStateNew}})
		mw := NewIdempotencyMiddleware(store, time.Minute)
		handler := mw.Middleware(scope)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotBody, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("downstream read body: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"size":` + strconv.Itoa(len(gotBody)) + `}`))
		}))

		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.RemoteAddr = "203.0.113.77:8080"
		if includeKey {
			req.Header.Set(idempotencyHeader, key)
		}
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		if routePattern != "" {
			routeCtx := chi.NewRouteContext()
			routeCtx.RoutePatterns = []string{routePattern}
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
		}
		if withClaims {
			req = req.WithContext(context.WithValue(req.Context(), ClaimsContextKey, &security.Claims{
				RegisteredClaims: jwt.RegisteredClaims{Subject: subject},
			}))
		}

		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		trimmed := strings.TrimSpace(key)
		if !includeKey || trimmed == "" || len(trimmed) > 128 {
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for invalid/missing key, got %d", rr.Code)
			}
			if len(*beginCalls) != 0 {
				t.Fatalf("expected no begin calls for invalid key path, got %d", len(*beginCalls))
			}
			return
		}

		if rr.Code != http.StatusCreated {
			t.Fatalf("expected 201 for valid key flow, got %d", rr.Code)
		}
		if len(*beginCalls) != 1 {
			t.Fatalf("expected one begin call, got %d", len(*beginCalls))
		}
		if len(*completeCalls) != 1 {
			t.Fatalf("expected one complete call, got %d", len(*completeCalls))
		}
		if (*beginCalls)[0].fingerprint == "" || (*completeCalls)[0].fingerprint == "" {
			t.Fatal("expected non-empty fingerprint")
		}
	})
}

func sanitizeFuzzPath(path string) string {
	path = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return '_'
		}
		return r
	}, path)
	path = strings.ReplaceAll(path, "%", "_")
	path = strings.ReplaceAll(path, "?", "_")
	path = strings.ReplaceAll(path, "#", "_")
	if path == "" || !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	// Ensure path is parsable by httptest.NewRequest URL handling.
	if _, err := url.Parse(path); err != nil {
		return "/fuzz"
	}
	return path
}

func sanitizeFuzzMethod(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
		return method
	default:
		return http.MethodPost
	}
}
