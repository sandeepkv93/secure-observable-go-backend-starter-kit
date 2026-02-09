package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/response"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/security"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
)

type UserHandler struct {
	userSvc    service.UserServiceInterface
	sessionSvc service.SessionServiceInterface
}

func NewUserHandler(userSvc service.UserServiceInterface, sessionSvc service.SessionServiceInterface) *UserHandler {
	return &UserHandler{
		userSvc:    userSvc,
		sessionSvc: sessionSvc,
	}
}

func (h *UserHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, _, err := authUserIDAndClaims(r)
	if err != nil {
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid user", nil)
		return
	}
	u, _, err := h.userSvc.GetByID(userID)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "user not found", nil)
		return
	}
	response.JSON(w, r, http.StatusOK, u)
}

func (h *UserHandler) Sessions(w http.ResponseWriter, r *http.Request) {
	userID, claims, err := authUserIDAndClaims(r)
	if err != nil {
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid user", nil)
		return
	}

	currentSessionID, err := h.sessionSvc.ResolveCurrentSessionID(r, claims, userID)
	if err != nil && !errors.Is(err, repository.ErrSessionNotFound) {
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to resolve current session", nil)
		return
	}
	sessionViews, err := h.sessionSvc.ListActiveSessions(userID, currentSessionID)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to list sessions", nil)
		return
	}

	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "session.list",
		ActorUserID: observability.ActorUserID(userID),
		TargetType:  "session",
		TargetID:    "self",
		Action:      "list",
		Outcome:     "success",
		Reason:      "sessions_loaded",
	}, "count", len(sessionViews), "current_session_id", currentSessionID)
	response.JSON(w, r, http.StatusOK, sessionViews)
}

func (h *UserHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID, _, err := authUserIDAndClaims(r)
	if err != nil {
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid user", nil)
		return
	}

	rawSessionID := chi.URLParam(r, "session_id")
	sessionID64, err := strconv.ParseUint(rawSessionID, 10, 64)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid session id", nil)
		return
	}
	sessionID := uint(sessionID64)

	status, err := h.sessionSvc.RevokeSession(userID, sessionID)
	if err != nil {
		if errors.Is(err, repository.ErrSessionNotFound) {
			response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "session not found", nil)
			return
		}
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to revoke session", nil)
		return
	}

	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "session.revoke.single",
		ActorUserID: observability.ActorUserID(userID),
		TargetType:  "session",
		TargetID:    strconv.FormatUint(uint64(sessionID), 10),
		Action:      "revoke",
		Outcome:     "success",
		Reason:      status,
	}, "status", status)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"session_id": sessionID,
		"status":     status,
	})
}

func (h *UserHandler) RevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	userID, claims, err := authUserIDAndClaims(r)
	if err != nil {
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid user", nil)
		return
	}

	currentSessionID, err := h.sessionSvc.ResolveCurrentSessionID(r, claims, userID)
	if err != nil {
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "unable to determine current session", nil)
		return
	}

	revokedCount, err := h.sessionSvc.RevokeOtherSessions(userID, currentSessionID)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to revoke other sessions", nil)
		return
	}

	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "session.revoke.others",
		ActorUserID: observability.ActorUserID(userID),
		TargetType:  "session",
		TargetID:    "others",
		Action:      "revoke",
		Outcome:     "success",
		Reason:      "bulk_revoke",
	}, "current_session_id", currentSessionID, "revoked_count", revokedCount)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"current_session_id": currentSessionID,
		"revoked_count":      revokedCount,
	})
}

func authUserIDAndClaims(r *http.Request) (uint, *security.Claims, error) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		return 0, nil, errors.New("missing auth context")
	}
	id64, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		return 0, nil, err
	}
	return uint(id64), claims, nil
}
