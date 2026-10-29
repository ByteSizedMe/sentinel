package httpapi

import (
	"fmt"
	"net/http"

	"github.com/bytesizedme/sentinel/internal/rbac"
)

// createPermissionRequest: a permission is an action on an existing resource.
type createPermissionRequest struct {
	Action     string `json:"action"`
	ResourceID int64  `json:"resource_id"`
}

func (a *api) createPermission(w http.ResponseWriter, r *http.Request) {
	var req createPermissionRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if err := rbac.ValidateName("action", req.Action); err != nil {
		writeError(w, r, err)
		return
	}
	if req.ResourceID <= 0 {
		writeError(w, r, fmt.Errorf("%w: resource_id must be a positive integer", rbac.ErrInvalidInput))
		return
	}
	p, err := a.store.CreatePermission(r.Context(), req.Action, req.ResourceID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

func (a *api) listPermissions(w http.ResponseWriter, r *http.Request) {
	perms, err := a.store.ListPermissions(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, perms)
}

func (a *api) getPermission(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "permissionID")
	if err != nil {
		writeError(w, r, err)
		return
	}
	p, err := a.store.GetPermission(r.Context(), id)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (a *api) deletePermission(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "permissionID")
	if err != nil {
		writeError(w, r, err)
		return
	}
	if err := a.store.DeletePermission(r.Context(), id); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
