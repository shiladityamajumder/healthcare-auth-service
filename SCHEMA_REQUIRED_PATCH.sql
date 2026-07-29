-- Run this through the external migration service. FastAPI must not execute it.
--
-- The original NULLS NOT DISTINCT phone constraint prevents multiple email-only
-- users because every (NULL, NULL) phone pair compares as equal. The replacement
-- enforces uniqueness only for complete phone pairs and rejects half-populated
-- phone identities.

BEGIN;

ALTER TABLE identity.users
    DROP CONSTRAINT IF EXISTS users_phone;

DROP INDEX IF EXISTS identity.users_phone;
DROP INDEX IF EXISTS identity.uq_identity_users_phone_present;

ALTER TABLE identity.users
    DROP CONSTRAINT IF EXISTS ck_identity_users_phone_pair_complete;

ALTER TABLE identity.users
    ADD CONSTRAINT ck_identity_users_phone_pair_complete
    CHECK (
        (phone_country_code IS NULL AND phone_number IS NULL)
        OR
        (phone_country_code IS NOT NULL AND phone_number IS NOT NULL)
    ) NOT VALID;

-- This intentionally fails if legacy rows contain incomplete phone identities.
-- Clean those rows in the migration service before retrying when necessary.
ALTER TABLE identity.users
    VALIDATE CONSTRAINT ck_identity_users_phone_pair_complete;

CREATE UNIQUE INDEX uq_identity_users_phone_present
    ON identity.users (phone_country_code, phone_number)
    WHERE phone_country_code IS NOT NULL
      AND phone_number IS NOT NULL;

COMMIT;
