package service

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/domain"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
	repogomock "github.com/sandeepkv93/everything-backend-starter-kit/internal/repository/gomock"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/security"
	"go.uber.org/mock/gomock"
)

func TestSessionServiceListActiveSessions(t *testing.T) {
	now := time.Now().UTC()
	revoked := now.Add(-time.Minute)

	ctrl := gomock.NewController(t)
	repo := repogomock.NewMockSessionRepository(ctrl)
	repo.EXPECT().ListActiveByUserID(uint(42)).Return([]domain.Session{
		{ID: 10, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(time.Hour), UserAgent: "ua1", IP: "1.1.1.1"},
		{ID: 11, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(2 * time.Hour), RevokedAt: &revoked, UserAgent: "ua2", IP: "2.2.2.2"},
	}, nil)
	svc := NewSessionService(repo, "pepper")

	views, err := svc.ListActiveSessions(42, 11)
	if err != nil {
		t.Fatalf("ListActiveSessions: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(views))
	}
	if views[0].IsCurrent {
		t.Fatal("expected first session not current")
	}
	if !views[1].IsCurrent {
		t.Fatal("expected second session current")
	}
	if views[1].RevokedAt == nil {
		t.Fatal("expected revoked_at to be mapped")
	}
}

func TestSessionServiceListActiveSessionsRepoError(t *testing.T) {
	expected := errors.New("db unavailable")
	ctrl := gomock.NewController(t)
	repo := repogomock.NewMockSessionRepository(ctrl)
	repo.EXPECT().ListActiveByUserID(uint(1)).Return(nil, expected)
	svc := NewSessionService(repo, "pepper")

	_, err := svc.ListActiveSessions(1, 0)
	if !errors.Is(err, expected) {
		t.Fatalf("expected %v, got %v", expected, err)
	}
}

func TestSessionServiceResolveCurrentSessionID(t *testing.T) {
	t.Run("claims token success", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := repogomock.NewMockSessionRepository(ctrl)
		repo.EXPECT().FindActiveByTokenIDForUser(uint(7), "token-123").Return(&domain.Session{ID: 77}, nil)

		svc := NewSessionService(repo, "pepper")
		req := httptest.NewRequest("GET", "/", nil)

		id, err := svc.ResolveCurrentSessionID(req, &security.Claims{
			RegisteredClaims: jwt.RegisteredClaims{ID: "token-123"},
		}, 7)
		if err != nil {
			t.Fatalf("ResolveCurrentSessionID: %v", err)
		}
		if id != 77 {
			t.Fatalf("expected session ID 77, got %d", id)
		}
	})

	t.Run("claims lookup unexpected error", func(t *testing.T) {
		expected := errors.New("db down")
		ctrl := gomock.NewController(t)
		repo := repogomock.NewMockSessionRepository(ctrl)
		repo.EXPECT().FindActiveByTokenIDForUser(uint(7), "token-123").Return(nil, expected)
		svc := NewSessionService(repo, "pepper")
		req := httptest.NewRequest("GET", "/", nil)

		_, err := svc.ResolveCurrentSessionID(req, &security.Claims{
			RegisteredClaims: jwt.RegisteredClaims{ID: "token-123"},
		}, 7)
		if !errors.Is(err, expected) {
			t.Fatalf("expected %v, got %v", expected, err)
		}
	})

	t.Run("claims not found falls back to cookie hash", func(t *testing.T) {
		refreshToken := "refresh-token"
		pepper := "p3pp3r"
		expectedHash := security.HashRefreshToken(refreshToken, pepper)

		ctrl := gomock.NewController(t)
		repo := repogomock.NewMockSessionRepository(ctrl)
		repo.EXPECT().FindActiveByTokenIDForUser(uint(7), "token-123").Return(nil, repository.ErrSessionNotFound)
		repo.EXPECT().FindByHash(expectedHash).Return(&domain.Session{ID: 42, UserID: 7, ExpiresAt: time.Now().Add(time.Hour)}, nil)
		svc := NewSessionService(repo, pepper)
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})

		id, err := svc.ResolveCurrentSessionID(req, &security.Claims{
			RegisteredClaims: jwt.RegisteredClaims{ID: "token-123"},
		}, 7)
		if err != nil {
			t.Fatalf("ResolveCurrentSessionID: %v", err)
		}
		if id != 42 {
			t.Fatalf("expected session ID 42, got %d", id)
		}
	})

	t.Run("missing cookie returns not found", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := repogomock.NewMockSessionRepository(ctrl)
		svc := NewSessionService(repo, "pepper")
		req := httptest.NewRequest("GET", "/", nil)

		_, err := svc.ResolveCurrentSessionID(req, nil, 7)
		if !errors.Is(err, repository.ErrSessionNotFound) {
			t.Fatalf("expected ErrSessionNotFound, got %v", err)
		}
	})

	t.Run("fallback hash repo error", func(t *testing.T) {
		expected := errors.New("redis unavailable")
		ctrl := gomock.NewController(t)
		repo := repogomock.NewMockSessionRepository(ctrl)
		repo.EXPECT().FindByHash(gomock.Any()).Return(nil, expected)
		svc := NewSessionService(repo, "pepper")
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh-token"})

		_, err := svc.ResolveCurrentSessionID(req, nil, 7)
		if !errors.Is(err, expected) {
			t.Fatalf("expected %v, got %v", expected, err)
		}
	})

	t.Run("fallback session rejected on mismatched user revoked or expired", func(t *testing.T) {
		cases := []struct {
			name    string
			session *domain.Session
		}{
			{name: "mismatched user", session: &domain.Session{ID: 1, UserID: 99, ExpiresAt: time.Now().Add(time.Hour)}},
			{name: "revoked", session: &domain.Session{ID: 1, UserID: 7, ExpiresAt: time.Now().Add(time.Hour), RevokedAt: ptrTime(time.Now())}},
			{name: "expired", session: &domain.Session{ID: 1, UserID: 7, ExpiresAt: time.Now().Add(-time.Minute)}},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ctrl := gomock.NewController(t)
				repo := repogomock.NewMockSessionRepository(ctrl)
				repo.EXPECT().FindByHash(gomock.Any()).Return(tc.session, nil)
				svc := NewSessionService(repo, "pepper")
				req := httptest.NewRequest("GET", "/", nil)
				req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "refresh-token"})

				_, err := svc.ResolveCurrentSessionID(req, nil, 7)
				if !errors.Is(err, repository.ErrSessionNotFound) {
					t.Fatalf("expected ErrSessionNotFound, got %v", err)
				}
			})
		}
	})
}

func TestSessionServiceRevokeSession(t *testing.T) {
	t.Run("repo error", func(t *testing.T) {
		expected := errors.New("update failed")
		ctrl := gomock.NewController(t)
		repo := repogomock.NewMockSessionRepository(ctrl)
		repo.EXPECT().RevokeByIDForUser(uint(1), uint(2), "user_session_revoked").Return(false, expected)
		svc := NewSessionService(repo, "pepper")

		_, err := svc.RevokeSession(1, 2)
		if !errors.Is(err, expected) {
			t.Fatalf("expected %v, got %v", expected, err)
		}
	})

	t.Run("already revoked", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := repogomock.NewMockSessionRepository(ctrl)
		repo.EXPECT().RevokeByIDForUser(uint(1), uint(2), "user_session_revoked").Return(false, nil)
		svc := NewSessionService(repo, "pepper")

		status, err := svc.RevokeSession(1, 2)
		if err != nil {
			t.Fatalf("RevokeSession: %v", err)
		}
		if status != "already_revoked" {
			t.Fatalf("expected already_revoked, got %q", status)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		repo := repogomock.NewMockSessionRepository(ctrl)
		repo.EXPECT().RevokeByIDForUser(uint(1), uint(2), "user_session_revoked").Return(true, nil)
		svc := NewSessionService(repo, "pepper")

		status, err := svc.RevokeSession(1, 2)
		if err != nil {
			t.Fatalf("RevokeSession: %v", err)
		}
		if status != "revoked" {
			t.Fatalf("expected revoked, got %q", status)
		}
	})
}

func TestSessionServiceRevokeOtherSessions(t *testing.T) {
	ctrl := gomock.NewController(t)
	repo := repogomock.NewMockSessionRepository(ctrl)
	repo.EXPECT().RevokeOthersByUser(uint(9), uint(3), "user_revoke_others").Return(int64(4), nil)
	svc := NewSessionService(repo, "pepper")

	n, err := svc.RevokeOtherSessions(9, 3)
	if err != nil {
		t.Fatalf("RevokeOtherSessions: %v", err)
	}
	if n != 4 {
		t.Fatalf("expected 4 revocations, got %d", n)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
