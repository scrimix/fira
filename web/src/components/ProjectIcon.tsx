// Centralized icon registry for projects.
//
// Anywhere a project icon is rendered (sidebar, topbar, modals, future
// integrations) goes through this component. Adding a new icon = one line
// in PROJECT_ICONS.
//
// Backwards compat: pre-Lucide projects stored a unicode glyph in icon
// (e.g. "◆"). If the value isn't in the registry, fall back to rendering
// it as text — so seed fixtures don't break.

import {
  Diamond, Triangle, Hexagon, Circle,
  Star, Sparkles, Zap, Flame,
  Compass, Rocket, Code2, Box,
  type LucideIcon,
} from 'lucide-react';

export const PROJECT_ICONS: { name: string; icon: LucideIcon }[] = [
  { name: 'Diamond',  icon: Diamond },
  { name: 'Triangle', icon: Triangle },
  { name: 'Hexagon',  icon: Hexagon },
  { name: 'Circle',   icon: Circle },
  { name: 'Star',     icon: Star },
  { name: 'Sparkles', icon: Sparkles },
  { name: 'Zap',      icon: Zap },
  { name: 'Flame',    icon: Flame },
  { name: 'Compass',  icon: Compass },
  { name: 'Rocket',   icon: Rocket },
  { name: 'Code2',    icon: Code2 },
  { name: 'Box',      icon: Box },
];

const REGISTRY = new Map(PROJECT_ICONS.map((p) => [p.name, p.icon]));

export const DEFAULT_ICON = 'Diamond';

interface Props {
  name: string;
  size?: number;
  color?: string;
  // Stroke width tweak — sidebar uses 1.75 to read at 16px; bigger renders
  // (modal preview, login mark) drop to 1.5 to feel less mechanical.
  strokeWidth?: number;
  className?: string;
  title?: string;
}

export function ProjectIcon({ name, size = 16, color, strokeWidth = 1.75, className, title }: Props) {
  const Icon = REGISTRY.get(name);
  if (Icon) {
    return (
      <Icon
        size={size}
        color={color}
        strokeWidth={strokeWidth}
        className={className}
        aria-label={title}
      />
    );
  }
  // Fallback: render the literal string (pre-Lucide glyphs like ◆).
  return (
    <span
      className={className}
      style={{ color, fontSize: size, lineHeight: 1 }}
      aria-label={title}
    >
      {name || '·'}
    </span>
  );
}
