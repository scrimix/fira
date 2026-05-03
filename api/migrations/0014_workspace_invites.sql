-- Email-based workspace invites.
--
-- Replaces the "search-and-pick from a global user list" flow for
-- adding workspace members. The owner enters an email; the server
-- creates a pending row keyed on (workspace_id, email). When the
-- recipient is logged in (or signs in) under that email, they see a
-- sticky modal — same pattern as user_links — and can accept or
-- decline. Accept inserts a row into workspace_members and fans out a
-- workspace.member_added op to existing members.
--
-- Email is canonicalized (lowercase + trim) at write time so duplicate
-- detection works across the inevitable casing variants.

CREATE TABLE workspace_invites (
    id            uuid primary key default gen_random_uuid(),
    workspace_id  uuid not null references workspaces(id) on delete cascade,
    email         text not null,
    role          text not null default 'member' check (role in ('member', 'lead')),
    status        text not null check (status in ('pending', 'accepted', 'declined', 'cancelled')),
    invited_by    uuid not null references users(id) on delete cascade,
    created_at    timestamptz not null default now(),
    resolved_at   timestamptz
);

-- One pending invite per (workspace, email). Re-inviting an email that
-- already has a pending invite is a no-op (server returns the existing
-- one); declined / cancelled invites can be re-sent.
CREATE UNIQUE INDEX workspace_invites_one_pending
    ON workspace_invites (workspace_id, email)
    WHERE status = 'pending';

-- Fast lookup for "what invites does this email have", driven by
-- bootstrap and user-channel nudges.
CREATE INDEX workspace_invites_by_email
    ON workspace_invites (email)
    WHERE status = 'pending';
