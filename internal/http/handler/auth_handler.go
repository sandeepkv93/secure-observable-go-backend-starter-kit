package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/response"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
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
	loginURL := h.authSvc.GoogleLoginURL(state)
	if loginURL == "" {
		status = "failure"
		observability.Audit(r, "auth.google.login.failed", "reason", "provider_disabled")
		observability.RecordAuthLogin(r.Context(), "google", "failure")
		response.Error(w, r, http.StatusNotFound, "NOT_ENABLED", "google auth is disabled", nil)
		return
	}
	signed := security.SignState(state, h.stateKey)
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: signed, Path: "/api/v1/auth/google", HttpOnly: true, Secure: h.cookieMgr.Secure, SameSite: h.cookieMgr.SameSite, Domain: h.cookieMgr.Domain, MaxAge: 300})
	observability.Audit(r, "auth.google.login.redirect")
	http.Redirect(w, r, loginURL, http.StatusFound)
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
		if errors.Is(err, service.ErrGoogleAuthDisabled) {
			response.Error(w, r, http.StatusNotFound, "NOT_ENABLED", "google auth is disabled", nil)
			return
		}
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

func (h *AuthHandler) LocalRegister(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAuthRequestDuration(r.Context(), "local_register", status, time.Since(start))
	}()
	var req struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status = "failure"
		observability.Audit(r, "auth.local.register.failed", "reason", "invalid_payload")
		observability.RecordAuthLogin(r.Context(), "local", "failure")
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	result, err := h.authSvc.RegisterLocal(req.Email, req.Name, req.Password, r.UserAgent(), clientIP(r))
	if err != nil {
		status = "failure"
		observability.Audit(r, "auth.local.register.failed", "reason", "service_error", "error", err.Error())
		observability.RecordAuthLogin(r.Context(), "local", "failure")
		switch {
		case errors.Is(err, service.ErrLocalAuthDisabled):
			response.Error(w, r, http.StatusNotFound, "NOT_ENABLED", "local auth is disabled", nil)
		case errors.Is(err, service.ErrWeakPassword):
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "password must be 12+ chars and include upper, lower, number, and special char", nil)
		default:
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		}
		return
	}
	if result.RequiresVerification {
		observability.Audit(r, "auth.local.register.pending_verification", "user_id", result.User.ID)
		response.JSON(w, r, http.StatusCreated, map[string]any{
			"user":                  result.User,
			"requires_verification": true,
		})
		return
	}
	h.cookieMgr.SetTokenCookies(w, result.AccessToken, result.RefreshToken, result.CSRFToken, h.refreshTTL)
	observability.Audit(r, "auth.local.register.success", "user_id", result.User.ID)
	observability.RecordAuthLogin(r.Context(), "local", "success")
	response.JSON(w, r, http.StatusCreated, map[string]any{"user": result.User, "csrf_token": result.CSRFToken, "expires_at": result.ExpiresAt})
}

func (h *AuthHandler) LocalLogin(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAuthRequestDuration(r.Context(), "local_login", status, time.Since(start))
	}()
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status = "failure"
		observability.Audit(r, "auth.local.login.failed", "reason", "invalid_payload")
		observability.RecordAuthLogin(r.Context(), "local", "failure")
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	result, err := h.authSvc.LoginWithLocalPassword(req.Email, req.Password, r.UserAgent(), clientIP(r))
	if err != nil {
		status = "failure"
		observability.Audit(r, "auth.local.login.failed", "reason", "login_error", "error", err.Error())
		observability.RecordAuthLogin(r.Context(), "local", "failure")
		switch {
		case errors.Is(err, service.ErrLocalAuthDisabled):
			response.Error(w, r, http.StatusNotFound, "NOT_ENABLED", "local auth is disabled", nil)
		case errors.Is(err, service.ErrLocalEmailUnverified):
			response.Error(w, r, http.StatusForbidden, "EMAIL_UNVERIFIED", "email verification required", nil)
		case errors.Is(err, service.ErrInvalidCredentials):
			response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials", nil)
		default:
			response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials", nil)
		}
		return
	}
	h.cookieMgr.SetTokenCookies(w, result.AccessToken, result.RefreshToken, result.CSRFToken, h.refreshTTL)
	observability.Audit(r, "auth.local.login.success", "user_id", result.User.ID)
	observability.RecordAuthLogin(r.Context(), "local", "success")
	response.JSON(w, r, http.StatusOK, map[string]any{"user": result.User, "csrf_token": result.CSRFToken, "expires_at": result.ExpiresAt})
}

func (h *AuthHandler) LocalChangePassword(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAuthRequestDuration(r.Context(), "local_change_password", status, time.Since(start))
	}()
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		status = "failure"
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "missing auth context", nil)
		return
	}
	userID, err := h.authSvc.ParseUserID(claims.Subject)
	if err != nil {
		status = "failure"
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid subject", nil)
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status = "failure"
		observability.Audit(r, "auth.local.change_password.failed", "reason", "invalid_payload", "user_id", userID)
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	if err := h.authSvc.ChangeLocalPassword(userID, req.CurrentPassword, req.NewPassword); err != nil {
		status = "failure"
		observability.Audit(r, "auth.local.change_password.failed", "reason", "change_error", "user_id", userID, "error", err.Error())
		switch {
		case errors.Is(err, service.ErrLocalAuthDisabled):
			response.Error(w, r, http.StatusNotFound, "NOT_ENABLED", "local auth is disabled", nil)
		case errors.Is(err, service.ErrWeakPassword):
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "password must be 12+ chars and include upper, lower, number, and special char", nil)
		case errors.Is(err, service.ErrInvalidCredentials):
			response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials", nil)
		default:
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		}
		return
	}
	h.cookieMgr.ClearTokenCookies(w)
	observability.Audit(r, "auth.local.change_password.success", "user_id", userID)
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "password_changed"})
}

func clientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	return r.RemoteAddr
}
