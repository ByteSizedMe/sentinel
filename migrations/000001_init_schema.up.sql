-- Resources are the things being protected (e.g. "invoices").
CREATE TABLE resources (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE roles (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A permission is "an action on a resource" (e.g. read on invoices).
-- Deleting a resource deletes the permissions that point at it.
CREATE TABLE permissions (
    id          BIGSERIAL PRIMARY KEY,
    action      TEXT NOT NULL,
    resource_id BIGINT NOT NULL REFERENCES resources (id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (action, resource_id)
);
CREATE INDEX idx_permissions_resource_id ON permissions (resource_id);

-- Many-to-many: which permissions a role grants.
-- The composite primary key already indexes role_id; permission_id needs its own index.
CREATE TABLE role_permissions (
    role_id       BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    permission_id BIGINT NOT NULL REFERENCES permissions (id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions (permission_id);

-- Which roles a user holds. user_id is plain text: users live in an external
-- identity system, not in this database.
CREATE TABLE user_roles (
    user_id TEXT   NOT NULL,
    role_id BIGINT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX idx_user_roles_role_id ON user_roles (role_id);
