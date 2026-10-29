package rbac

import "time"

// Role is a named bundle of permissions that can be assigned to users.
type Role struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// Resource is something that can be protected, e.g. "invoices".
type Resource struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// Permission allows one action (e.g. "read") on one resource.
type Permission struct {
	ID         int64     `json:"id"`
	Action     string    `json:"action"`
	ResourceID int64     `json:"resource_id"`
	CreatedAt  time.Time `json:"created_at"`
}
