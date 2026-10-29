package httpapi

import (
	"fmt"
	"net/http"

	"github.com/bytesizedme/sentinel/internal/rbac"
	"github.com/go-chi/chi/v5"
)

// Handlers for the two relationships: role <-> permission and user <-> role.

type grantRequest struct {
	PermissionID int64 `json:"permission_id"`
}

type assignRequest struct {
	RoleID int64 `json:"role_id"`
}

// grantPermission handles POST /v1/roles/{roleID}/permissions.
func (a *api) grantPermission(w http.ResponseWriter, r *http.Request) {
	roleID, err := pathID(r, "roleID")
	if err != nil {
		writeError(w, r, err)
		return
	}
	var req grantRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if req.PermissionID <= 0 {
		writeError(w, r, fmt.Errorf("%w: permission_id must be a positive integer", rbac.ErrInvalidInput))
		return
	}
	if err := a.store.GrantPermission(r.Context(), roleID, req.PermissionID); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"role_id": roleID, "permission_id": req.PermissionID})
}

// revokePermission handles DELETE /v1/roles/{roleID}/permissions/{permissionID}.
func (a *api) revokePermission(w http.ResponseWriter, r *http.Request) {
	roleID, err := pathID(r, "roleID")
	if err != nil {
		writeError(w, r, err)
		return
	}
	permID, err := pathID(r, "permissionID")
	if err != nil {
		writeError(w, r, err)
		return
	}
	if err := a.store.RevokePermission(r.Context(), roleID, permID); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listRolePermissions handles GET /v1/roles/{roleID}/permissions.
func (a *api) listRolePermissions(w http.ResponseWriter, r *http.Request) {
	roleID, err := pathID(r, "roleID")
	if err != nil {
		writeError(w, r, err)
		return
	}
	// Check the role exists so an unknown role is a 404, not an empty list.
	if _, err := a.store.GetRole(r.Context(), roleID); err != nil {
		writeError(w, r, err)
		return
	}
	perms, err := a.store.ListRolePermissions(r.Context(), roleID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, perms)
}

// userID reads and validates the {userID} URL parameter.
func userID(r *http.Request) (string, error) {
	id := chi.URLParam(r, "userID")
	if err := rbac.ValidateUserID(id); err != nil {
		return "", err
	}
	return id, nil
}

// assignRole handles POST /v1/users/{userID}/roles.
func (a *api) assignRole(w http.ResponseWriter, r *http.Request) {
	uid, err := userID(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	var req assignRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if req.RoleID <= 0 {
		writeError(w, r, fmt.Errorf("%w: role_id must be a positive integer", rbac.ErrInvalidInput))
		return
	}
	if err := a.store.AssignRole(r.Context(), uid, req.RoleID); err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user_id": uid, "role_id": req.RoleID})
}

// removeRole handles DELETE /v1/users/{userID}/roles/{roleID}.
func (a *api) removeRole(w http.ResponseWriter, r *http.Request) {
	uid, err := userID(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	roleID, err := pathID(r, "roleID")
	if err != nil {
		writeError(w, r, err)
		return
	}
	if err := a.store.RemoveRole(r.Context(), uid, roleID); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listUserRoles handles GET /v1/users/{userID}/roles.
func (a *api) listUserRoles(w http.ResponseWriter, r *http.Request) {
	uid, err := userID(r)
	if err != nil {
		writeError(w, r, err)
		return
	}
	roles, err := a.store.ListUserRoles(r.Context(), uid)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, roles)
}
