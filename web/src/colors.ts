// Shared project, tag and track palette — balanced step-9 hues with
// clear hue separation that hold up in both themes under the tint
// formula (see --tint-* in globals.css). Old → new mapping lives in
// api/migrations/0040_palette_v2.sql.
export const EDITORIAL_COLORS: { hex: string; name: string }[] = [
  { hex: '#12A594', name: 'Teal' },
  { hex: '#00A2C7', name: 'Cyan' },
  { hex: '#3E6AE1', name: 'Blue' },
  { hex: '#8E4EC6', name: 'Violet' },
  { hex: '#D6409F', name: 'Pink' },
  { hex: '#F76B15', name: 'Amber' },
  { hex: '#E5484D', name: 'Red' },
  { hex: '#E2A336', name: 'Yellow' },
  { hex: '#8B8D98', name: 'Graphite' },
  { hex: '#7CB342', name: 'Lime' },
  { hex: '#29A383', name: 'Emerald' },
  { hex: '#0D8FE0', name: 'Sky' },
  { hex: '#5B5BD6', name: 'Indigo' },
  { hex: '#AB4ABA', name: 'Fuchsia' },
  { hex: '#30A46C', name: 'Green' },
  { hex: '#6E7A8F', name: 'Slate' },
];
