-- Invite links carry a signed token naming one of these rows; the row is what makes them revocable.
CREATE TABLE invites (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID        NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    role         TEXT        NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    created_by   BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    max_uses     INTEGER     CHECK (max_uses > 0),
    uses         INTEGER     NOT NULL DEFAULT 0,
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX invites_workspace ON invites (workspace_id);
