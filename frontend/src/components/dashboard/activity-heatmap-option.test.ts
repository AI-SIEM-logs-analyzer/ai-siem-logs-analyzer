import { CHART_COLORS } from '@/components/charts/chart-theme';
import {
  activityHeatmapOption,
  heatmapColors,
} from '@/components/dashboard/activity-heatmap-option';
import { densityLevels, type ActivityHeatmap } from '@/lib/heatmap';

const HOUR = 60 * 60 * 1000;
const FROM = Date.parse('2026-09-30T00:00:00Z');

const heatmap: ActivityHeatmap = {
  columns: [FROM, FROM + HOUR],
  bucketMs: HOUR,
  rows: [
    {
      ip: '<img src=x onerror=alert(1)>',
      total: 12,
      cells: [
        { start: FROM, count: 12 },
        { start: FROM + HOUR, count: 0 },
      ],
    },
    {
      ip: '198.51.100.2',
      total: 1,
      cells: [
        { start: FROM, count: 0 },
        { start: FROM + HOUR, count: 1 },
      ],
    },
  ],
};

type Formatter = (params: { value: number[] }) => string;

describe('activityHeatmapOption', () => {
  const levels = densityLevels(12);
  const option = activityHeatmapOption(heatmap, { levels, labelWidth: 112, dark: false });

  it('draws an address per row, busiest on top, and a cell for every bucket', () => {
    expect(option.yAxis).toMatchObject({
      type: 'category',
      inverse: true,
      data: ['<img src=x onerror=alert(1)>', '198.51.100.2'],
    });
    const [series] = option.series as { type: string; data: number[][] }[];
    expect(series.type).toBe('heatmap');
    expect(series.data).toEqual([
      [0, 0, 12],
      [1, 0, 0],
      [0, 1, 0],
      [1, 1, 1],
    ]);
  });

  it('colours a cell by its band, the fullest darkest, and an empty one faintly', () => {
    const fills = heatmapColors(levels.length, false);

    expect(option.visualMap).toMatchObject({
      type: 'piecewise',
      show: false,
      dimension: 2,
      pieces: [
        { min: 0, max: 0, color: fills.empty },
        ...levels.map((level, i) => ({ min: level.from, max: level.to, color: fills.levels[i] })),
      ],
    });
    expect(fills.levels.at(-1)).toBe(CHART_COLORS.light.heat.at(-1));
  });

  it('escapes the address in the tooltip', () => {
    const { formatter } = option.tooltip as { formatter: Formatter };
    const html = formatter({ value: [0, 0, 12] });

    expect(html).toContain('12 events');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).not.toContain('<img');
    expect(formatter({ value: [1, 0, 0] })).toContain('No events');
  });

  it('takes its colours from the mode', () => {
    expect(heatmapColors(5, true).levels).toEqual(CHART_COLORS.dark.heat);
    expect(heatmapColors(5, true).empty).toBe(CHART_COLORS.dark.heatEmpty);
  });
});
