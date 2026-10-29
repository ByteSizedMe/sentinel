package rbac

import "context"

// PolicyStore is where roles, permissions, resources and their relationships
// are kept. The HTTP layer depends on this interface, not on Postgres, so
// tests can use an in-memory fake.
//
// Implementations must return only the sentinel errors in errors.go for
// expected failures: ErrNotFound (missing row or missing referenced row),
// ErrConflict (duplicate). Anything else is an unexpected internal error.
type PolicyStore interface {
	CreateRole(ctx context.Context, name, description string) (Role, error)
	GetRole(ctx context.Context, id int64) (Role, error)
	ListRoles(ctx context.Context) ([]Role, error)
	DeleteRole(ctx context.Context, id int64) error

	CreateResource(ctx context.Context, name, description string) (Resource, error)
	GetResource(ctx context.Context, id int64) (Resource, error)
	ListResources(ctx context.Context) ([]Resource, error)
	DeleteResource(ctx context.Context, id int64) error

	CreatePermission(ctx context.Context, action string, resourceID int64) (Permission, error)
	GetPermission(ctx context.Context, id int64) (Permission, error)
	ListPermissions(ctx context.Context) ([]Permission, error)
	DeletePermission(ctx context.Context, id int64) error

	GrantPermission(ctx context.Context, roleID, permissionID int64) error
	RevokePermission(ctx context.Context, roleID, permissionID int64) error
	ListRolePermissions(ctx context.Context, roleID int64) ([]Permission, error)

	AssignRole(ctx context.Context, userID string, roleID int64) error
	RemoveRole(ctx context.Context, userID string, roleID int64) error
	ListUserRoles(ctx context.Context, userID string) ([]Role, error)
}
