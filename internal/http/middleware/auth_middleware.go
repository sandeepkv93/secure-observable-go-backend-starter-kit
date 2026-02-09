package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/response"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
)

type contextKey string

const (
	ClaimsContextKey contextKey = "claims"
)

func AuthMiddleware(jwtMgr *security.JWTManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := security.GetCookie(r, "access_token")
			if raw == "" {
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
					raw = strings.TrimSpace(auth[7:])
				}
			}
			if raw == "" {
				response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "missing access token", nil)
				return
			}
			claims, err := jwtMgr.ParseAccessToken(raw)
			if err != nil {
				response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid access token", nil)
				return
			}
			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func ClaimsFromContext(ctx context.Context) (*security.Claims, bool) {
	c, ok := ctx.Value(ClaimsContextKey).(*security.Claims)
	return c, ok
}
