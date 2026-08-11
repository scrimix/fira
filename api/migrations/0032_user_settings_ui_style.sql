-- Shape/density axis, orthogonal to `theme` (which picks the palette).
-- 'classic' keeps the original square-edged, compact editorial look;
-- 'modern' rounds corners, softens elevation and loosens density.
ALTER TABLE user_settings
  ADD COLUMN ui_style TEXT NOT NULL DEFAULT 'classic'
    CHECK (ui_style IN ('classic', 'modern'));
