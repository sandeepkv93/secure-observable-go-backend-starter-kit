package middleware

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
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

type fakeIdempotencyStore struct {
	beginResult service.IdempotencyBeginResult
	beginErr    error
	completeErr error

	beginCalls    []beginCall
	completeCalls []completeCall
}

func (s *fakeIdempotencyStore) Begin(_ context.Context, scope, key, fingerprint string, ttl time.Duration) (service.IdempotencyBeginResult, error) {
	s.beginCalls = append(s.beginCalls, beginCall{scope: scope, key: key, fingerprint: fingerprint, ttl: ttl})
	if s.beginErr != nil {
		return service.IdempotencyBeginResult{}, s.beginErr
	}
	return s.beginResult, nil
}

func (s *fakeIdempotencyStore) Complete(_ context.Context, scope, key, fingerprint string, response service.CachedHTTPResponse, ttl time.Duration) error {
	s.completeCalls = append(s.completeCalls, completeCall{
		scope:       scope,
		key:         key,
		fingerprint: fingerprint,
		response:    response,
		ttl:         ttl,
	})
	return s.completeErr
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
			store := &fakeIdempotencyStore{}
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
			if len(store.beginCalls) != 0 {
				t.Fatalf("expected no begin calls, got %d", len(store.beginCalls))
			}
		})
	}
}

func TestIdempotencyMiddlewareRejectsUnreadableBody(t *testing.T) {
	store := &fakeIdempotencyStore{}
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
	if len(store.beginCalls) != 0 {
		t.Fatalf("expected no begin calls on body read error, got %d", len(store.beginCalls))
	}
}

func TestIdempotencyMiddlewareBeginErrorReturnsInternal(t *testing.T) {
	store := &fakeIdempotencyStore{beginErr: errors.New("redis unavailable")}
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
	if len(store.beginCalls) != 1 {
		t.Fatalf("expected one begin call, got %d", len(store.beginCalls))
	}
	if len(store.completeCalls) != 0 {
		t.Fatalf("expected no complete calls when begin fails, got %d", len(store.completeCalls))
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
			store := &fakeIdempotencyStore{beginResult: service.IdempotencyBeginResult{State: tc.beginState, Cached: tc.cached}}
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
			if len(store.completeCalls) != 0 {
				t.Fatalf("expected no complete calls for begin state %s, got %d", tc.beginState, len(store.completeCalls))
			}
		})
	}
}

func TestIdempotencyMiddlewareCompleteBehavior(t *testing.T) {
	t.Run("downstream 5xx does not persist complete", func(t *testing.T) {
		store := &fakeIdempotencyStore{beginResult: service.IdempotencyBeginResult{State: service.IdempotencyStateNew}}
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
		if len(store.completeCalls) != 0 {
			t.Fatalf("expected no complete calls for 5xx response, got %d", len(store.completeCalls))
		}
	})

	t.Run("complete store failure does not fail response", func(t *testing.T) {
		store := &fakeIdempotencyStore{
			beginResult: service.IdempotencyBeginResult{State: service.IdempotencyStateNew},
			completeErr: errors.New("complete failed"),
		}
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
		if len(store.completeCalls) != 1 {
			t.Fatalf("expected one complete call, got %d", len(store.completeCalls))
		}
		cc := store.completeCalls[0]
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
