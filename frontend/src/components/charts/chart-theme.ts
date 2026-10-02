// ECharts paints with concrete colours, not CSS variables, so the theme's tokens are mirrored
// here: a single series is blue, everything else the neutral greys of the shadcn/ui theme in
// index.css. The status colours are fixed across modes and reserved for status (HTTP classes);
// they never stand in for a series, and always come with a label.
//
// `heat` is the sequential ramp for magnitude (the activity heatmap), one blue hue, faintest
// first: in light mode it darkens away from the white surface, in dark mode it lightens away from
// the dark one, so the fullest cells stand out in both. `heatEmpty` fills a cell with no events.
export const CHART_COLORS = {
  light: {
    bar: '#2a78d6',
    barHover: '#256abf',
    text: '#737373',
    ink: '#0a0a0a',
    grid: '#e5e5e5',
    surface: '#ffffff',
    pointer: '#a3a3a3',
    heat: ['#b7d3f6', '#86b6ef', '#5598e7', '#256abf', '#104281'],
    heatEmpty: '#f5f5f5',
  },
  dark: {
    bar: '#3987e5',
    barHover: '#5598e7',
    text: '#a1a1a1',
    ink: '#fafafa',
    grid: '#ffffff1a',
    surface: '#171717',
    pointer: '#525252',
    heat: ['#104281', '#1c5cab', '#2a78d6', '#5598e7', '#9ec5f4'],
    heatEmpty: '#ffffff0d',
  },
} as const;

export type ChartColors = (typeof CHART_COLORS)[keyof typeof CHART_COLORS];

export const STATUS_COLORS = {
  neutral: '#a3a3a3',
  info: '#2a78d6',
  good: '#0ca30c',
  warning: '#fab219',
  critical: '#d03b3b',
} as const;

export function prefersDark(): boolean {
  return document.documentElement.classList.contains('dark');
}

export function chartColors(dark = prefersDark()): ChartColors {
  return dark ? CHART_COLORS.dark : CHART_COLORS.light;
}

export const count = new Intl.NumberFormat();

export function formatEvents(n: number): string {
  return `${count.format(n)} ${n === 1 ? 'event' : 'events'}`;
}

const ENTITIES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

/** For text from the backend (an IP, a log message) going into a tooltip's HTML. */
export function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (char) => ENTITIES[char]);
}
