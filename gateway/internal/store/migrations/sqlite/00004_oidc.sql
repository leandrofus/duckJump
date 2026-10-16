-- +goose Up
-- Users from an OpenID Connect provider are matched by "<issuer>|<sub>",
-- never by username: a name taken by a local account cannot be claimed
-- through the identity provider.
ALTER TABLE config_users ADD COLUMN oidc_subject TEXT;
CREATE UNIQUE INDEX config_users_oidc_subject ON config_users (oidc_subject) WHERE oidc_subject IS NOT NULL;

-- +goose Down
DROP INDEX config_users_oidc_subject;
ALTER TABLE config_users DROP COLUMN oidc_subject;
