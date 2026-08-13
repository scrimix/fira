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
  Briefcase, Folder, Flag, Target, Layers, Calendar, ClipboardList,
  BookOpen, Lightbulb, Heart, Coffee, Music, Camera, Palette, PenTool,
  Globe2, Map as MapIcon, Plane, Car, Home, Users, Shield, Lock, Wrench, Settings,
  Database, Terminal, Bug, GitBranch, Package, ShoppingBag, BarChart3,
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
  { name: 'Briefcase', icon: Briefcase },
  { name: 'Folder',    icon: Folder },
  { name: 'Flag',      icon: Flag },
  { name: 'Target',    icon: Target },
  { name: 'Layers',    icon: Layers },
  { name: 'Calendar',  icon: Calendar },
  { name: 'ClipboardList', icon: ClipboardList },
  { name: 'BookOpen',  icon: BookOpen },
  { name: 'Lightbulb', icon: Lightbulb },
  { name: 'Heart',     icon: Heart },
  { name: 'Coffee',    icon: Coffee },
  { name: 'Music',     icon: Music },
  { name: 'Camera',    icon: Camera },
  { name: 'Palette',   icon: Palette },
  { name: 'PenTool',   icon: PenTool },
  { name: 'Globe2',    icon: Globe2 },
  { name: 'Map',       icon: MapIcon },
  { name: 'Plane',     icon: Plane },
  { name: 'Car',       icon: Car },
  { name: 'Home',      icon: Home },
  { name: 'Users',     icon: Users },
  { name: 'Shield',    icon: Shield },
  { name: 'Lock',      icon: Lock },
  { name: 'Wrench',    icon: Wrench },
  { name: 'Settings',  icon: Settings },
  { name: 'Database',  icon: Database },
  { name: 'Terminal',  icon: Terminal },
  { name: 'Bug',       icon: Bug },
  { name: 'GitBranch', icon: GitBranch },
  { name: 'Package',   icon: Package },
  { name: 'ShoppingBag', icon: ShoppingBag },
  { name: 'BarChart3', icon: BarChart3 },
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
