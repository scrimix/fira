-- Palette v2: remap the old saturated project/tag/track colours to the
-- balanced palette in web/src/colors.ts (1:1 by hue name).
-- Colours outside the old palette are left untouched.

UPDATE projects SET color = CASE lower(color)
        WHEN '#0f766e' THEN '#12A594'
        WHEN '#0e7490' THEN '#00A2C7'
        WHEN '#1d4ed8' THEN '#3E6AE1'
        WHEN '#6d28d9' THEN '#8E4EC6'
        WHEN '#be185d' THEN '#D6409F'
        WHEN '#b45309' THEN '#F76B15'
        WHEN '#dc2626' THEN '#E5484D'
        WHEN '#ca8a04' THEN '#E2A336'
        WHEN '#71717a' THEN '#8B8D98'
        WHEN '#4d7c0f' THEN '#7CB342'
        WHEN '#047857' THEN '#29A383'
        WHEN '#0369a1' THEN '#0D8FE0'
        WHEN '#4338ca' THEN '#5B5BD6'
        WHEN '#a21caf' THEN '#AB4ABA'
        WHEN '#15803d' THEN '#30A46C'
        WHEN '#334155' THEN '#6E7A8F'
    END
WHERE lower(color) IN ('#0f766e', '#0e7490', '#1d4ed8', '#6d28d9', '#be185d', '#b45309', '#dc2626', '#ca8a04', '#71717a', '#4d7c0f', '#047857', '#0369a1', '#4338ca', '#a21caf', '#15803d', '#334155');

UPDATE tags SET color = CASE lower(color)
        WHEN '#0f766e' THEN '#12A594'
        WHEN '#0e7490' THEN '#00A2C7'
        WHEN '#1d4ed8' THEN '#3E6AE1'
        WHEN '#6d28d9' THEN '#8E4EC6'
        WHEN '#be185d' THEN '#D6409F'
        WHEN '#b45309' THEN '#F76B15'
        WHEN '#dc2626' THEN '#E5484D'
        WHEN '#ca8a04' THEN '#E2A336'
        WHEN '#71717a' THEN '#8B8D98'
        WHEN '#4d7c0f' THEN '#7CB342'
        WHEN '#047857' THEN '#29A383'
        WHEN '#0369a1' THEN '#0D8FE0'
        WHEN '#4338ca' THEN '#5B5BD6'
        WHEN '#a21caf' THEN '#AB4ABA'
        WHEN '#15803d' THEN '#30A46C'
        WHEN '#334155' THEN '#6E7A8F'
    END
WHERE lower(color) IN ('#0f766e', '#0e7490', '#1d4ed8', '#6d28d9', '#be185d', '#b45309', '#dc2626', '#ca8a04', '#71717a', '#4d7c0f', '#047857', '#0369a1', '#4338ca', '#a21caf', '#15803d', '#334155');

UPDATE tracks SET color = CASE lower(color)
        WHEN '#0f766e' THEN '#12A594'
        WHEN '#0e7490' THEN '#00A2C7'
        WHEN '#1d4ed8' THEN '#3E6AE1'
        WHEN '#6d28d9' THEN '#8E4EC6'
        WHEN '#be185d' THEN '#D6409F'
        WHEN '#b45309' THEN '#F76B15'
        WHEN '#dc2626' THEN '#E5484D'
        WHEN '#ca8a04' THEN '#E2A336'
        WHEN '#71717a' THEN '#8B8D98'
        WHEN '#4d7c0f' THEN '#7CB342'
        WHEN '#047857' THEN '#29A383'
        WHEN '#0369a1' THEN '#0D8FE0'
        WHEN '#4338ca' THEN '#5B5BD6'
        WHEN '#a21caf' THEN '#AB4ABA'
        WHEN '#15803d' THEN '#30A46C'
        WHEN '#334155' THEN '#6E7A8F'
    END
WHERE lower(color) IN ('#0f766e', '#0e7490', '#1d4ed8', '#6d28d9', '#be185d', '#b45309', '#dc2626', '#ca8a04', '#71717a', '#4d7c0f', '#047857', '#0369a1', '#4338ca', '#a21caf', '#15803d', '#334155');

ALTER TABLE tracks ALTER COLUMN color SET DEFAULT '#6E7A8F';
