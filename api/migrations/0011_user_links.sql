-- Account linking ("link two accounts").
--
-- Two users can link their accounts so each sees the other's tasks and
-- time blocks read-only on the calendar. Motivated by the work-life
-- balance case: a person owns two accounts (personal Gmail + work
-- Google), and the calendar should reflect the *one* real timeline of
-- that person rather than fragmenting it across accounts.
--
-- Pair canonicalization: user_a_id < user_b_id so a single row exists
-- per unordered pair. `requested_by` distinguishes who initiated.
--
-- One accepted link per user — the partial unique indexes enforce it,
-- so a user can't accumulate links. Pending requests can stack up to
-- multiple targets but only one can be accepted.

CREATE TABLE user_links (
    id            uuid primary key default gen_random_uuid(),
    user_a_id     uuid not null references users(id) on delete cascade,
    user_b_id     uuid not null references users(id) on delete cascade,
    requested_by  uuid not null references users(id) on delete cascade,
    status        text not null check (status in ('pending', 'accepted')),
    created_at    timestamptz not null default now(),
    accepted_at   timestamptz,
    check (user_a_id < user_b_id),
    check (requested_by in (user_a_id, user_b_id)),
    unique (user_a_id, user_b_id)
);

-- One accepted link per user — enforced by partial unique on each side.
CREATE UNIQUE INDEX user_links_one_accepted_a
    ON user_links (user_a_id) WHERE status = 'accepted';
CREATE UNIQUE INDEX user_links_one_accepted_b
    ON user_links (user_b_id) WHERE status = 'accepted';
