-- Sprint 35: task-cli attachments.
--
-- The CLI compares attachments by filename + content hash, so it never
-- re-uploads an unchanged file. NULL = unknown (rows uploaded before this
-- migration): the first CLI fetch that covers the task reads the file
-- once, hashes it and stores the hash.
ALTER TABLE attachments ADD COLUMN sha256 TEXT;
