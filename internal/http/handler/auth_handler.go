package handler

import (
	"net/http"
	"strings"
	"time"

	"go-oauth-rbac-service/internal/http/middleware"
	"go-oauth-rbac-service/internal/http/response"
	"go-oauth-rbac-service/internal/observability"
	"go-oauth-rbac-service/internal/security"
	"go-oauth-rbac-service/internal/service"
)

type AuthHandler struct {
	authSvc    service.AuthServiceInterface
	cookieMgr  *security.CookieManager
	stateKey   string
	refreshTTL time.Duration
}

func NewAuthHandler(authSvc service.AuthServiceInterface, cookieMgr *security.CookieManager, stateKey string, refreshTTL time.Duration) *AuthHandler {
	return &AuthHandler{authSvc: authSvc, cookieMgr: cookieMgr, stateKey: stateKey, refreshTTL: refreshTTL}
}

func (h *AuthHandler) GoogleLogin(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAuthRequestDuration(r.Context(), "google_login", status, time.Since(start))
	}()

	state, err := security.NewRandomString(24)
	if err != nil {
		status = "failure"
		observability.Audit(r, "auth.google.login.failed", "reason", "state_generation")
		observability.RecordAuthLogin(r.Context(), "google", "failure")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to generate oauth state", nil)
		return
	}
	signed := security.SignState(state, h.stateKey)
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: signed, Path: "/api/v1/auth/google", HttpOnly: true, Secure: h.cookieMgr.Secure, SameSite: h.cookieMgr.SameSite, Domain: h.cookieMgr.Domain, MaxAge: 300})
	observability.Audit(r, "auth.google.login.redirect")
	http.Redirect(w, r, h.authSvc.GoogleLoginURL(state), http.StatusFound)
}

func (h *AuthHandler) GoogleCallback(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAuthRequestDuration(r.Context(), "google_callback", status, time.Since(start))
	}()

	queryState := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if queryState == "" || code == "" {
		status = "failure"
		observability.Audit(r, "auth.google.callback.failed", "reason", "missing_code_or_state")
		observability.RecordAuthLogin(r.Context(), "google", "failure")
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "missing state or code", nil)
		return
	}
	stateCookie := security.GetCookie(r, "oauth_state")
	state, ok := security.VerifySignedState(stateCookie, h.stateKey)
	if !ok || state != queryState {
		status = "failure"
		observability.Audit(r, "auth.google.callback.failed", "reason", "invalid_state")
		observability.RecordAuthLogin(r.Context(), "google", "failure")
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid oauth state", nil)
		return
	}
	// Invalidate one-time state immediately after successful verification.
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: "", Path: "/api/v1/auth/google", MaxAge: -1, HttpOnly: true, Secure: h.cookieMgr.Secure, SameSite: h.cookieMgr.SameSite, Domain: h.cookieMgr.Domain})

	result, err := h.authSvc.LoginWithGoogleCode(code, r.UserAgent(), clientIP(r))
	if err != nil {
		status = "failure"
		observability.Audit(r, "auth.google.callback.failed", "reason", "oauth_exchange", "error", err.Error())
		observability.RecordAuthLogin(r.Context(), "google", "failure")
		response.Error(w, r, http.StatusUnauthorized, "OAUTH_FAILED", err.Error(), nil)
		return
	}
	h.cookieMgr.SetTokenCookies(w, result.AccessToken, result.RefreshToken, result.CSRFToken, h.refreshTTL)
	observability.Audit(r, "auth.login.success", "user_id", result.User.ID, "provider", "google")
	observability.RecordAuthLogin(r.Context(), "google", "success")
	response.JSON(w, r, http.StatusOK, map[string]any{"user": result.User, "csrf_token": result.CSRFToken, "expires_at": result.ExpiresAt})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAuthRequestDuration(r.Context(), "refresh", status, time.Since(start))
	}()

	refresh := security.GetCookie(r, "refresh_token")
	if refresh == "" {
		status = "failure"
		observability.Audit(r, "auth.refresh.failed", "reason", "missing_refresh_cookie")
		observability.RecordAuthRefresh(r.Context(), "failure")
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "missing refresh token", nil)
		return
	}
	result, err := h.authSvc.Refresh(refresh, r.UserAgent(), clientIP(r))
	if err != nil {
		status = "failure"
		observability.Audit(r, "auth.refresh.failed", "reason", "invalid_refresh")
		observability.RecordAuthRefresh(r.Context(), "failure")
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid refresh token", nil)
		return
	}
	h.cookieMgr.SetTokenCookies(w, result.AccessToken, result.RefreshToken, result.CSRFToken, h.refreshTTL)
	observability.Audit(r, "auth.refresh.success", "user_id", result.User.ID)
	observability.RecordAuthRefresh(r.Context(), "success")
	response.JSON(w, r, http.StatusOK, map[string]any{"user": result.User, "csrf_token": result.CSRFToken, "expires_at": result.ExpiresAt})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAuthRequestDuration(r.Context(), "logout", status, time.Since(start))
	}()

	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		status = "failure"
		observability.Audit(r, "auth.logout.failed", "reason", "missing_auth_context")
		observability.RecordAuthLogout(r.Context(), "failure")
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "missing auth context", nil)
		return
	}
	uid, err := h.authSvc.ParseUserID(claims.Subject)
	if err != nil {
		status = "failure"
		observability.Audit(r, "auth.logout.failed", "reason", "invalid_subject")
		observability.RecordAuthLogout(r.Context(), "failure")
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid subject", nil)
		return
	}
	if err := h.authSvc.Logout(uid); err != nil {
		status = "failure"
		observability.Audit(r, "auth.logout.failed", "user_id", uid, "reason", "revoke_error")
		observability.RecordAuthLogout(r.Context(), "failure")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "logout failed", nil)
		return
	}
	h.cookieMgr.ClearTokenCookies(w)
	observability.Audit(r, "auth.logout.success", "user_id", uid)
	observability.RecordAuthLogout(r.Context(), "success")
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "logged_out"})
}

func clientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	return r.RemoteAddr
}
