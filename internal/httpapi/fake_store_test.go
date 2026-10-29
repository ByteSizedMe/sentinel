package httpapi

import (
	"context"
	"sort"
	"time"

	"github.com/bytesizedme/sentinel/internal/rbac"
)

// fakeStore is an in-memory rbac.PolicyStore for handler tests. It mimics the
// Postgres behaviour we rely on: unique names, missing references -> ErrNotFound,
// duplicates -> ErrConflict, and cascading deletes. Tests are sequential, so no locking.
type fakeStore struct {
	lastID      map[string]int64 // one counter per table, like separate Postgres sequences
	roles       map[int64]rbac.Role
	resources   map[int64]rbac.Resource
	permissions map[int64]rbac.Permission
	grants      map[[2]int64]bool  // {roleID, permissionID}
	assigns     map[string][]int64 // userID -> role IDs
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		lastID:      map[string]int64{},
		roles:       map[int64]rbac.Role{},
		resources:   map[int64]rbac.Resource{},
		permissions: map[int64]rbac.Permission{},
		grants:      map[[2]int64]bool{},
		assigns:     map[string][]int64{},
	}
}

func (f *fakeStore) id(table string) int64 { f.lastID[table]++; return f.lastID[table] }

func (f *fakeStore) CreateRole(_ context.Context, name, desc string) (rbac.Role, error) {
	for _, r := range f.roles {
		if r.Name == name {
			return rbac.Role{}, rbac.ErrConflict
		}
	}
	r := rbac.Role{ID: f.id("roles"), Name: name, Description: desc, CreatedAt: time.Now()}
	f.roles[r.ID] = r
	return r, nil
}

func (f *fakeStore) GetRole(_ context.Context, id int64) (rbac.Role, error) {
	r, ok := f.roles[id]
	if !ok {
		return rbac.Role{}, rbac.ErrNotFound
	}
	return r, nil
}

func (f *fakeStore) ListRoles(context.Context) ([]rbac.Role, error) {
	out := []rbac.Role{}
	for _, r := range f.roles {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeStore) DeleteRole(_ context.Context, id int64) error {
	if _, ok := f.roles[id]; !ok {
		return rbac.ErrNotFound
	}
	delete(f.roles, id)
	for k := range f.grants { // cascade, like ON DELETE CASCADE
		if k[0] == id {
			delete(f.grants, k)
		}
	}
	for u, ids := range f.assigns {
		f.assigns[u] = without(ids, id)
	}
	return nil
}

func (f *fakeStore) CreateResource(_ context.Context, name, desc string) (rbac.Resource, error) {
	for _, r := range f.resources {
		if r.Name == name {
			return rbac.Resource{}, rbac.ErrConflict
		}
	}
	r := rbac.Resource{ID: f.id("resources"), Name: name, Description: desc, CreatedAt: time.Now()}
	f.resources[r.ID] = r
	return r, nil
}

func (f *fakeStore) GetResource(_ context.Context, id int64) (rbac.Resource, error) {
	r, ok := f.resources[id]
	if !ok {
		return rbac.Resource{}, rbac.ErrNotFound
	}
	return r, nil
}

func (f *fakeStore) ListResources(context.Context) ([]rbac.Resource, error) {
	out := []rbac.Resource{}
	for _, r := range f.resources {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeStore) DeleteResource(_ context.Context, id int64) error {
	if _, ok := f.resources[id]; !ok {
		return rbac.ErrNotFound
	}
	delete(f.resources, id)
	for pid, p := range f.permissions { // cascade to permissions and their grants
		if p.ResourceID == id {
			f.deletePermission(pid)
		}
	}
	return nil
}

func (f *fakeStore) CreatePermission(_ context.Context, action string, resourceID int64) (rbac.Permission, error) {
	if _, ok := f.resources[resourceID]; !ok {
		return rbac.Permission{}, rbac.ErrNotFound
	}
	for _, p := range f.permissions {
		if p.Action == action && p.ResourceID == resourceID {
			return rbac.Permission{}, rbac.ErrConflict
		}
	}
	p := rbac.Permission{ID: f.id("permissions"), Action: action, ResourceID: resourceID, CreatedAt: time.Now()}
	f.permissions[p.ID] = p
	return p, nil
}

func (f *fakeStore) GetPermission(_ context.Context, id int64) (rbac.Permission, error) {
	p, ok := f.permissions[id]
	if !ok {
		return rbac.Permission{}, rbac.ErrNotFound
	}
	return p, nil
}

func (f *fakeStore) ListPermissions(context.Context) ([]rbac.Permission, error) {
	out := []rbac.Permission{}
	for _, p := range f.permissions {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeStore) DeletePermission(_ context.Context, id int64) error {
	if _, ok := f.permissions[id]; !ok {
		return rbac.ErrNotFound
	}
	f.deletePermission(id)
	return nil
}

func (f *fakeStore) deletePermission(id int64) {
	delete(f.permissions, id)
	for k := range f.grants {
		if k[1] == id {
			delete(f.grants, k)
		}
	}
}

func (f *fakeStore) GrantPermission(_ context.Context, roleID, permID int64) error {
	if _, ok := f.roles[roleID]; !ok {
		return rbac.ErrNotFound
	}
	if _, ok := f.permissions[permID]; !ok {
		return rbac.ErrNotFound
	}
	if f.grants[[2]int64{roleID, permID}] {
		return rbac.ErrConflict
	}
	f.grants[[2]int64{roleID, permID}] = true
	return nil
}

func (f *fakeStore) RevokePermission(_ context.Context, roleID, permID int64) error {
	k := [2]int64{roleID, permID}
	if !f.grants[k] {
		return rbac.ErrNotFound
	}
	delete(f.grants, k)
	return nil
}

func (f *fakeStore) ListRolePermissions(_ context.Context, roleID int64) ([]rbac.Permission, error) {
	out := []rbac.Permission{}
	for k := range f.grants {
		if k[0] == roleID {
			out = append(out, f.permissions[k[1]])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeStore) AssignRole(_ context.Context, userID string, roleID int64) error {
	if _, ok := f.roles[roleID]; !ok {
		return rbac.ErrNotFound
	}
	for _, id := range f.assigns[userID] {
		if id == roleID {
			return rbac.ErrConflict
		}
	}
	f.assigns[userID] = append(f.assigns[userID], roleID)
	return nil
}

func (f *fakeStore) RemoveRole(_ context.Context, userID string, roleID int64) error {
	ids := f.assigns[userID]
	rest := without(ids, roleID)
	if len(rest) == len(ids) {
		return rbac.ErrNotFound
	}
	f.assigns[userID] = rest
	return nil
}

func (f *fakeStore) ListUserRoles(_ context.Context, userID string) ([]rbac.Role, error) {
	out := []rbac.Role{}
	for _, id := range f.assigns[userID] {
		out = append(out, f.roles[id])
	}
	return out, nil
}

// without returns ids minus one value.
func without(ids []int64, drop int64) []int64 {
	var out []int64
	for _, id := range ids {
		if id != drop {
			out = append(out, id)
		}
	}
	return out
}
