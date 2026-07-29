-- Reference only. Apply through the external migration and seed service.
BEGIN;

INSERT INTO identity.roles (
    id, code, name, description, is_system,
    created_at, updated_at, row_version, is_deleted
)
VALUES
    (gen_random_uuid(), 'customer', 'Customer', 'Default ecommerce customer role', true,
     now(), now(), 1, false),
    (gen_random_uuid(), 'identity_admin', 'Identity Administrator',
     'Administrative identity and API-client management role', true,
     now(), now(), 1, false)
ON CONFLICT DO NOTHING;

INSERT INTO identity.permissions (
    id, code, resource, action, description,
    created_at, updated_at, row_version, is_deleted
)
VALUES
    (gen_random_uuid(), 'identity.api_clients.manage', 'identity.api_clients',
     'manage', 'Create, rotate, and revoke machine API clients',
     now(), now(), 1, false),
    (gen_random_uuid(), 'identity.users.manage', 'identity.users',
     'manage', 'Create, lock, unlock, and revoke sessions for users',
     now(), now(), 1, false)
ON CONFLICT DO NOTHING;

INSERT INTO identity.role_permissions (
    id, role_id, permission_id,
    created_at, updated_at, row_version
)
SELECT
    gen_random_uuid(),
    role.id,
    permission.id,
    now(), now(), 1
FROM identity.roles AS role
JOIN identity.permissions AS permission
    ON permission.code IN (
        'identity.api_clients.manage',
        'identity.users.manage'
    )
WHERE role.code = 'identity_admin'
  AND role.is_deleted = false
  AND permission.is_deleted = false
  AND NOT EXISTS (
      SELECT 1
      FROM identity.role_permissions existing
      WHERE existing.role_id = role.id
        AND existing.permission_id = permission.id
  );

COMMIT;
