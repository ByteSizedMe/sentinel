package httpapi

import "net/http"

func (a *api) createResource(w http.ResponseWriter, r *http.Request) {
	var req nameRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, err)
		return
	}
	if err := validateNameRequest(req); err != nil {
		writeError(w, r, err)
		return
	}
	res, err := a.store.CreateResource(r.Context(), req.Name, req.Description)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, res)
}

func (a *api) listResources(w http.ResponseWriter, r *http.Request) {
	resources, err := a.store.ListResources(r.Context())
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, resources)
}

func (a *api) getResource(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "resourceID")
	if err != nil {
		writeError(w, r, err)
		return
	}
	res, err := a.store.GetResource(r.Context(), id)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *api) deleteResource(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r, "resourceID")
	if err != nil {
		writeError(w, r, err)
		return
	}
	if err := a.store.DeleteResource(r.Context(), id); err != nil {
		writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
