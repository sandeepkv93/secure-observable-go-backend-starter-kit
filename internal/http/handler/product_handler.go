package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/sandeepkv93/everything-backend-starter-kit/internal/http/response"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/observability"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/repository"
	"github.com/sandeepkv93/everything-backend-starter-kit/internal/service"
)

type ProductHandler struct {
	svc service.ProductService
}

func NewProductHandler(svc service.ProductService) *ProductHandler {
	return &ProductHandler{svc: svc}
}

func (h *ProductHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string  `json:"name"`
		Description string  `json:"description"`
		Price       float64 `json:"price"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}

	created, err := h.svc.Create(r.Context(), service.CreateProductInput{
		Name:        body.Name,
		Description: body.Description,
		Price:       body.Price,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrProductInvalidName),
			errors.Is(err, service.ErrProductInvalidDescription),
			errors.Is(err, service.ErrProductInvalidPrice):
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
			return
		case isConflictError(err):
			response.Error(w, r, http.StatusConflict, "CONFLICT", "product already exists", nil)
			return
		default:
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to create product", nil)
			return
		}
	}

	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "product.create",
		ActorUserID: adminActorID(r),
		TargetType:  "product",
		TargetID:    strconv.FormatUint(uint64(created.ID), 10),
		Action:      "create",
		Outcome:     "success",
		Reason:      "product_created",
	}, "name", created.Name)
	response.JSON(w, r, http.StatusCreated, created)
}

func (h *ProductHandler) List(w http.ResponseWriter, r *http.Request) {
	pageReq, err := parsePageRequest(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}

	res, err := h.svc.ListPaged(r.Context(), pageReq)
	if err != nil {
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to list products", nil)
		return
	}
	response.JSON(w, r, http.StatusOK, paginatedData(res.Items, res.Page, res.PageSize, res.Total, res.TotalPages))
}

func (h *ProductHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	productID, err := parsePathID(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid product id", nil)
		return
	}

	product, err := h.svc.GetByID(r.Context(), productID)
	if err != nil {
		if errors.Is(err, repository.ErrProductNotFound) {
			response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "product not found", nil)
			return
		}
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to load product", nil)
		return
	}
	response.JSON(w, r, http.StatusOK, product)
}

func (h *ProductHandler) Update(w http.ResponseWriter, r *http.Request) {
	productID, err := parsePathID(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid product id", nil)
		return
	}
	var body struct {
		Name        *string  `json:"name"`
		Description *string  `json:"description"`
		Price       *float64 `json:"price"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid payload", nil)
		return
	}

	updated, err := h.svc.Update(r.Context(), productID, service.UpdateProductInput{
		Name:        body.Name,
		Description: body.Description,
		Price:       body.Price,
	})
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrProductNotFound):
			response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "product not found", nil)
			return
		case errors.Is(err, service.ErrProductInvalidName),
			errors.Is(err, service.ErrProductInvalidDescription),
			errors.Is(err, service.ErrProductInvalidPrice),
			errors.Is(err, service.ErrProductNoUpdates):
			response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
			return
		default:
			response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to update product", nil)
			return
		}
	}

	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "product.update",
		ActorUserID: adminActorID(r),
		TargetType:  "product",
		TargetID:    strconv.FormatUint(uint64(productID), 10),
		Action:      "update",
		Outcome:     "success",
		Reason:      "product_updated",
	}, "name", strings.TrimSpace(updated.Name))
	response.JSON(w, r, http.StatusOK, updated)
}

func (h *ProductHandler) Delete(w http.ResponseWriter, r *http.Request) {
	productID, err := parsePathID(chi.URLParam(r, "id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, "BAD_REQUEST", "invalid product id", nil)
		return
	}

	if err := h.svc.DeleteByID(r.Context(), productID); err != nil {
		if errors.Is(err, repository.ErrProductNotFound) {
			response.Error(w, r, http.StatusNotFound, "NOT_FOUND", "product not found", nil)
			return
		}
		response.Error(w, r, http.StatusInternalServerError, "INTERNAL", "failed to delete product", nil)
		return
	}

	observability.EmitAudit(r, observability.AuditInput{
		EventName:   "product.delete",
		ActorUserID: adminActorID(r),
		TargetType:  "product",
		TargetID:    strconv.FormatUint(uint64(productID), 10),
		Action:      "delete",
		Outcome:     "success",
		Reason:      "product_deleted",
	})
	response.JSON(w, r, http.StatusOK, map[string]any{"deleted": true})
}
