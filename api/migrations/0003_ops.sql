-- Outbox sync: idempotency log.
--
-- Every op sent by a client carries a UUID (`op_id`) generated at mutation
-- time. When we apply it server-side, we record it here. A retry of the
-- same op_id (network blip, double-fire) finds the row already exists and
-- short-circuits — the mutation runs at most once per op_id.

CREATE TABLE processed_ops (
    op_id       TEXT PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_processed_ops_user_applied ON processed_ops(user_id, applied_at);
