package handler

import (
	"encoding/json"
	"errors"
	"fmt"
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
	abuseGuard service.AuthAbuseGuard
	cookieMgr  *security.CookieManager
	stateKey   string
	refreshTTL time.Duration
}

func NewAuthHandler(
	authSvc service.AuthServiceInterface,
	abuseGuard service.AuthAbuseGuard,
	cookieMgr *security.CookieManager,
	stateKey string,
	refreshTTL time.Duration,
) *AuthHandler {
	if abuseGuard == nil {
		abuseGuard = service.NewNoopAuthAbuseGuard()
	}
	return &AuthHandler{
		authSvc:    authSvc,
		abuseGuard: abuseGuard,
		cookieMgr:  cookieMgr,
		stateKey:   stateKey,
		refreshTTL: refreshTTL,
	}
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
		auditAuth(r, "auth.google.login", "oauth_login", "failure", "state_generation", "anonymous", "auth_provider", "google")
		observability.RecordAuthLogin(r.Context(), "google", "failure")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to generate oauth state", nil)
		return
	}
	loginURL := h.authSvc.GoogleLoginURL(state)
	if loginURL == "" {
		status = "failure"
		auditAuth(r, "auth.google.login", "oauth_login", "rejected", "provider_disabled", "anonymous", "auth_provider", "google")
		observability.RecordAuthLogin(r.Context(), "google", "failure")
		response.Error(w, r, http.StatusNotFound, "NOT_ENABLED", "google auth is disabled", nil)
		return
	}
	signed := security.SignState(state, h.stateKey)
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: signed, Path: "/api/v1/auth/google", HttpOnly: true, Secure: h.cookieMgr.Secure, SameSite: h.cookieMgr.SameSite, Domain: h.cookieMgr.Domain, MaxAge: 300})
	auditAuth(r, "auth.google.login", "oauth_login", "success", "redirect_issued", "anonymous", "auth_provider", "google")
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
		auditAuth(r, "auth.google.callback", "oauth_callback", "failure", "missing_code_or_state", "anonymous", "auth_provider", "google")
		observability.RecordAuthLogin(r.Context(), "google", "failure")
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "missing state or code", nil)
		return
	}
	stateCookie := security.GetCookie(r, "oauth_state")
	state, ok := security.VerifySignedState(stateCookie, h.stateKey)
	if !ok || state != queryState {
		status = "failure"
		auditAuth(r, "auth.google.callback", "oauth_callback", "failure", "invalid_state", "anonymous", "auth_provider", "google")
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
		auditAuth(r, "auth.google.callback", "oauth_callback", "failure", "oauth_exchange_error", "anonymous", "auth_provider", "google", "error", err.Error())
		observability.RecordAuthLogin(r.Context(), "google", "failure")
		response.Error(w, r, http.StatusUnauthorized, "OAUTH_FAILED", err.Error(), nil)
		return
	}
	h.cookieMgr.SetTokenCookies(w, result.AccessToken, result.RefreshToken, result.CSRFToken, h.refreshTTL)
	auditAuth(r, "auth.login", "login", "success", "oauth_google", observability.ActorUserID(result.User.ID), "user", observability.ActorUserID(result.User.ID), "provider", "google")
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
		auditAuth(r, "auth.refresh", "refresh", "failure", "missing_refresh_cookie", "anonymous", "session", "unknown")
		observability.RecordAuthRefresh(r.Context(), "failure")
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "missing refresh token", nil)
		return
	}
	result, err := h.authSvc.Refresh(refresh, r.UserAgent(), clientIP(r))
	if err != nil {
		status = "failure"
		reason := "invalid_refresh"
		metricStatus := "failure"
		if errors.Is(err, service.ErrRefreshTokenReuseDetected) {
			reason = "refresh_reuse_detected"
			metricStatus = "reuse_detected"
		}
		auditAuth(r, "auth.refresh", "refresh", "failure", reason, "anonymous", "session", "unknown")
		observability.RecordAuthRefresh(r.Context(), metricStatus)
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid refresh token", nil)
		return
	}
	h.cookieMgr.SetTokenCookies(w, result.AccessToken, result.RefreshToken, result.CSRFToken, h.refreshTTL)
	auditAuth(r, "auth.refresh", "refresh", "success", "token_rotated", observability.ActorUserID(result.User.ID), "user", observability.ActorUserID(result.User.ID))
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
		auditAuth(r, "auth.logout", "logout", "failure", "missing_auth_context", "anonymous", "session", "unknown")
		observability.RecordAuthLogout(r.Context(), "failure")
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "missing auth context", nil)
		return
	}
	uid, err := h.authSvc.ParseUserID(claims.Subject)
	if err != nil {
		status = "failure"
		auditAuth(r, "auth.logout", "logout", "failure", "invalid_subject", "anonymous", "session", "unknown")
		observability.RecordAuthLogout(r.Context(), "failure")
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid subject", nil)
		return
	}
	if err := h.authSvc.Logout(uid); err != nil {
		status = "failure"
		auditAuth(r, "auth.logout", "logout", "failure", "revoke_error", observability.ActorUserID(uid), "user", observability.ActorUserID(uid))
		observability.RecordAuthLogout(r.Context(), "failure")
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "logout failed", nil)
		return
	}
	h.cookieMgr.ClearTokenCookies(w)
	auditAuth(r, "auth.logout", "logout", "success", "sessions_revoked", observability.ActorUserID(uid), "user", observability.ActorUserID(uid))
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
		auditAuth(r, "auth.local.register", "register", "failure", "invalid_payload", "anonymous", "user", "unknown")
		observability.RecordAuthLogin(r.Context(), "local", "failure")
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	result, err := h.authSvc.RegisterLocal(req.Email, req.Name, req.Password, r.UserAgent(), clientIP(r))
	if err != nil {
		status = "failure"
		auditAuth(r, "auth.local.register", "register", "failure", "service_error", "anonymous", "user", "unknown", "error", err.Error())
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
		auditAuth(r, "auth.local.register", "register", "accepted", "verification_required", observability.ActorUserID(result.User.ID), "user", observability.ActorUserID(result.User.ID))
		response.JSON(w, r, http.StatusCreated, map[string]any{
			"user":                  result.User,
			"requires_verification": true,
		})
		return
	}
	h.cookieMgr.SetTokenCookies(w, result.AccessToken, result.RefreshToken, result.CSRFToken, h.refreshTTL)
	auditAuth(r, "auth.local.register", "register", "success", "session_created", observability.ActorUserID(result.User.ID), "user", observability.ActorUserID(result.User.ID))
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
		auditAuth(r, "auth.local.login", "login", "failure", "invalid_payload", "anonymous", "user", "unknown")
		observability.RecordAuthLogin(r.Context(), "local", "failure")
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	retryAfter, err := h.abuseGuard.Check(r.Context(), service.AuthAbuseScopeLogin, req.Email, clientIP(r))
	if err != nil {
		status = "failure"
		auditAuth(r, "auth.local.login", "login", "failure", "abuse_check_error", "anonymous", "user", "unknown", "error", err.Error())
		writeAbuseCooldownHeaders(w, retryAfter)
		response.Error(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests", nil)
		return
	}
	if retryAfter > 0 {
		status = "failure"
		auditAuth(r, "auth.local.login", "login", "rejected", "abuse_cooldown", "anonymous", "user", "unknown")
		writeAbuseCooldownHeaders(w, retryAfter)
		response.Error(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests", nil)
		return
	}
	result, err := h.authSvc.LoginWithLocalPassword(req.Email, req.Password, r.UserAgent(), clientIP(r))
	if err != nil {
		status = "failure"
		_, abuseErr := h.abuseGuard.RegisterFailure(r.Context(), service.AuthAbuseScopeLogin, req.Email, clientIP(r))
		if abuseErr != nil {
			auditAuth(r, "auth.local.login", "login", "failure", "abuse_record_error", "anonymous", "user", "unknown", "error", abuseErr.Error())
		}
		auditAuth(r, "auth.local.login", "login", "failure", "login_error", "anonymous", "user", "unknown", "error", err.Error())
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
	if err := h.abuseGuard.Reset(r.Context(), service.AuthAbuseScopeLogin, req.Email, clientIP(r)); err != nil {
		auditAuth(r, "auth.local.login", "login", "failure", "abuse_reset_error", observability.ActorUserID(result.User.ID), "user", observability.ActorUserID(result.User.ID), "error", err.Error())
	}
	h.cookieMgr.SetTokenCookies(w, result.AccessToken, result.RefreshToken, result.CSRFToken, h.refreshTTL)
	auditAuth(r, "auth.local.login", "login", "success", "credentials_valid", observability.ActorUserID(result.User.ID), "user", observability.ActorUserID(result.User.ID))
	observability.RecordAuthLogin(r.Context(), "local", "success")
	response.JSON(w, r, http.StatusOK, map[string]any{"user": result.User, "csrf_token": result.CSRFToken, "expires_at": result.ExpiresAt})
}

func (h *AuthHandler) LocalVerifyRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAuthRequestDuration(r.Context(), "local_verify_request", status, time.Since(start))
	}()
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status = "failure"
		auditAuth(r, "auth.local.verify.request", "verify_request", "failure", "invalid_payload", "anonymous", "user", "unknown")
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	if err := h.authSvc.RequestLocalEmailVerification(req.Email); err != nil {
		status = "failure"
		auditAuth(r, "auth.local.verify.request", "verify_request", "failure", "service_error", "anonymous", "user", "unknown", "error", err.Error())
		switch {
		case errors.Is(err, service.ErrLocalAuthDisabled):
			response.Error(w, r, http.StatusNotFound, "NOT_ENABLED", "local auth is disabled", nil)
		default:
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		}
		return
	}
	auditAuth(r, "auth.local.verify.request", "verify_request", "accepted", "verification_token_issued", "anonymous", "user", "unknown")
	response.JSON(w, r, http.StatusAccepted, map[string]string{"status": "verification_requested"})
}

func (h *AuthHandler) LocalVerifyConfirm(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAuthRequestDuration(r.Context(), "local_verify_confirm", status, time.Since(start))
	}()
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status = "failure"
		auditAuth(r, "auth.local.verify.confirm", "verify_confirm", "failure", "invalid_payload", "anonymous", "verification_token", "unknown")
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	if err := h.authSvc.ConfirmLocalEmailVerification(req.Token); err != nil {
		status = "failure"
		auditAuth(r, "auth.local.verify.confirm", "verify_confirm", "failure", "service_error", "anonymous", "verification_token", "unknown", "error", err.Error())
		switch {
		case errors.Is(err, service.ErrLocalAuthDisabled):
			response.Error(w, r, http.StatusNotFound, "NOT_ENABLED", "local auth is disabled", nil)
		case errors.Is(err, service.ErrInvalidVerifyToken):
			response.Error(w, r, http.StatusBadRequest, "INVALID_OR_EXPIRED_TOKEN", "invalid or expired token", nil)
		default:
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		}
		return
	}
	auditAuth(r, "auth.local.verify.confirm", "verify_confirm", "success", "email_verified", "anonymous", "verification_token", "consumed")
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "email_verified"})
}

func (h *AuthHandler) LocalPasswordForgot(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAuthRequestDuration(r.Context(), "local_password_forgot", status, time.Since(start))
	}()
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status = "failure"
		auditAuth(r, "auth.local.password.forgot", "password_forgot", "failure", "invalid_payload", "anonymous", "user", "unknown")
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	retryAfter, err := h.abuseGuard.Check(r.Context(), service.AuthAbuseScopeForgot, req.Email, clientIP(r))
	if err != nil {
		status = "failure"
		auditAuth(r, "auth.local.password.forgot", "password_forgot", "failure", "abuse_check_error", "anonymous", "user", "unknown", "error", err.Error())
		writeAbuseCooldownHeaders(w, retryAfter)
		response.Error(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests", nil)
		return
	}
	if retryAfter > 0 {
		status = "failure"
		auditAuth(r, "auth.local.password.forgot", "password_forgot", "rejected", "abuse_cooldown", "anonymous", "user", "unknown")
		writeAbuseCooldownHeaders(w, retryAfter)
		response.Error(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests", nil)
		return
	}
	if err := h.authSvc.ForgotLocalPassword(req.Email); err != nil {
		status = "failure"
		auditAuth(r, "auth.local.password.forgot", "password_forgot", "failure", "service_error", "anonymous", "user", "unknown", "error", err.Error())
		switch {
		case errors.Is(err, service.ErrLocalAuthDisabled):
			response.Error(w, r, http.StatusNotFound, "NOT_ENABLED", "local auth is disabled", nil)
		default:
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "password reset request failed", nil)
		}
		return
	}
	if _, err := h.abuseGuard.RegisterFailure(r.Context(), service.AuthAbuseScopeForgot, req.Email, clientIP(r)); err != nil {
		status = "failure"
		auditAuth(r, "auth.local.password.forgot", "password_forgot", "failure", "abuse_record_error", "anonymous", "user", "unknown", "error", err.Error())
		writeAbuseCooldownHeaders(w, retryAfter)
		response.Error(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests", nil)
		return
	}
	auditAuth(r, "auth.local.password.forgot", "password_forgot", "accepted", "reset_requested", "anonymous", "user", "unknown")
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "if the account exists, reset instructions were sent"})
}

func (h *AuthHandler) LocalPasswordReset(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	status := "success"
	defer func() {
		observability.RecordAuthRequestDuration(r.Context(), "local_password_reset", status, time.Since(start))
	}()
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		status = "failure"
		auditAuth(r, "auth.local.password.reset", "password_reset", "failure", "invalid_payload", "anonymous", "password_reset_token", "unknown")
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	if err := h.authSvc.ResetLocalPassword(req.Token, req.NewPassword); err != nil {
		status = "failure"
		auditAuth(r, "auth.local.password.reset", "password_reset", "failure", "service_error", "anonymous", "password_reset_token", "unknown", "error", err.Error())
		switch {
		case errors.Is(err, service.ErrLocalAuthDisabled):
			response.Error(w, r, http.StatusNotFound, "NOT_ENABLED", "local auth is disabled", nil)
		case errors.Is(err, service.ErrWeakPassword):
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "password must be 12+ chars and include upper, lower, number, and special char", nil)
		case errors.Is(err, service.ErrInvalidVerifyToken):
			response.Error(w, r, http.StatusBadRequest, "INVALID_OR_EXPIRED_TOKEN", "invalid or expired token", nil)
		default:
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "password reset failed", nil)
		}
		return
	}
	auditAuth(r, "auth.local.password.reset", "password_reset", "success", "password_updated", "anonymous", "password_reset_token", "consumed")
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "password_reset"})
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
		auditAuth(r, "auth.local.change_password", "password_change", "failure", "invalid_payload", observability.ActorUserID(userID), "user", observability.ActorUserID(userID))
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}
	if err := h.authSvc.ChangeLocalPassword(userID, req.CurrentPassword, req.NewPassword); err != nil {
		status = "failure"
		auditAuth(r, "auth.local.change_password", "password_change", "failure", "change_error", observability.ActorUserID(userID), "user", observability.ActorUserID(userID), "error", err.Error())
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
	auditAuth(r, "auth.local.change_password", "password_change", "success", "password_updated", observability.ActorUserID(userID), "user", observability.ActorUserID(userID))
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

func writeAbuseCooldownHeaders(w http.ResponseWriter, retryAfter time.Duration) {
	seconds := int(retryAfter.Round(time.Second).Seconds())
	if seconds <= 0 {
		seconds = 1
	}
	resetAt := time.Now().Add(time.Duration(seconds) * time.Second).Unix()
	w.Header().Set("Retry-After", fmt.Sprintf("%d", seconds))
	w.Header().Set("X-RateLimit-Limit", "0")
	w.Header().Set("X-RateLimit-Remaining", "0")
	w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", resetAt))
}

func auditAuth(r *http.Request, eventName, action, outcome, reason, actorUserID, targetType, targetID string, attrs ...any) {
	observability.EmitAudit(r, observability.AuditInput{
		EventName:   eventName,
		ActorUserID: actorUserID,
		TargetType:  targetType,
		TargetID:    targetID,
		Action:      action,
		Outcome:     outcome,
		Reason:      reason,
	}, attrs...)
}
