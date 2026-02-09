package handler

import (
	"net/http"
	"strconv"

	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/middleware"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/http/response"
	"github.com/sandeepkv93/secure-observable-go-backend-starter-kit/internal/service"
)

type UserHandler struct {
	userSvc service.UserServiceInterface
}

func NewUserHandler(userSvc service.UserServiceInterface) *UserHandler {
	return &UserHandler{userSvc: userSvc}
}

func (h *UserHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := middleware.ClaimsFromContext(r.Context())
	if !ok {
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "missing auth context", nil)
		return
	}
	id64, err := strconv.ParseUint(claims.Subject, 10, 64)
	if err != nil {
		response.Error(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid user", nil)
		return
	}
	u, _, err := h.userSvc.GetByID(uint(id64))
	if err != nil {
		response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "user not found", nil)
		return
	}
	response.JSON(w, r, http.StatusOK, u)
}
