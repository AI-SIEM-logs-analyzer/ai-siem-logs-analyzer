// ECharts paints with concrete colours, not CSS variables, so the theme's tokens are mirrored
// here: a single series is blue, everything else the neutral greys of the shadcn/ui theme in
// index.css. The status colours are fixed across modes and reserved for status (HTTP classes);
// they never stand in for a series, and always come with a label.
export const CHART_COLORS = {
  light: {
    bar: '#2a78d6',
    barHover: '#256abf',
    text: '#737373',
    ink: '#0a0a0a',
    grid: '#e5e5e5',
    surface: '#ffffff',
    pointer: '#a3a3a3',
  },
  dark: {
    bar: '#3987e5',
    barHover: '#5598e7',
    text: '#a1a1a1',
    ink: '#fafafa',
    grid: '#ffffff1a',
    surface: '#171717',
    pointer: '#525252',
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
