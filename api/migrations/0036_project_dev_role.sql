-- Dev members work with plans and tasks, but only see their own time blocks.
ALTER TABLE project_members DROP CONSTRAINT project_members_role_check;
ALTER TABLE project_members ADD CONSTRAINT project_members_role_check
    CHECK (role IN ('owner', 'lead', 'member', 'dev', 'inactive'));

-- Keep owner identity after a block is deleted. This is server-controlled,
-- with no FK: the durable change log outlives the user/block records.
ALTER TABLE processed_ops ADD COLUMN block_user_id UUID;
