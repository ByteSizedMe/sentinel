package httpapi

import (
	"net/http"

	"github.com/bytesizedme/sentinel/internal/rbac"
)

// nameRequest is the body for creating a role or a resource.
type nameRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

func (a *api) createRole(w http.ResponseWriter, r *http.Request) {
	var req nameRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if err := validateNameRequest(req); err != nil {
		writeError(w, r, err)
		return
	}
	role, err := a.store.CreateRole(r.Context(), req.Name, req.Description)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

func (a *api) listRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := a.store.ListRoles(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, roles)
}

func (a *api) getRole(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "roleID")
	if err != nil {
		writeError(w, r, err)
		return
	}
	role, err := a.store.GetRole(r.Context(), id)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, role)
}

func (a *api) deleteRole(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "roleID")
	if err != nil {
		writeError(w, r, err)
		return
	}
	if err := a.store.DeleteRole(r.Context(), id); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validateNameRequest(req nameRequest) error {
	if err := rbac.ValidateName("name", req.Name); err != nil {
		return err
	}
	return rbac.ValidateDescription(req.Description)
}
