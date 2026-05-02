-- Add 'inactive' to project_members.role. Mirrors the 'owner' visibility
-- rule but for regular members: an inactive member stays in the project
-- (history, prior assignments stay valid) but doesn't render an assignee
-- group in the inbox unless they have a Now task assigned. Use it for
-- people who joined a project but aren't actively contributing.
--
-- Authority unchanged: 'inactive' carries no edit power, same as 'member'.

ALTER TABLE project_members DROP CONSTRAINT project_members_role_check;
ALTER TABLE project_members
    ADD CONSTRAINT project_members_role_check
    CHECK (role IN ('owner','lead','member','inactive'));
