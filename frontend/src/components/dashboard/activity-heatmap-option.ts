import { chartColors, escapeHtml, formatEvents } from '@/components/charts/chart-theme';
import type { EChartOption } from '@/components/charts/echart';
import { columnLabel, levelColors, type ActivityHeatmap, type DensityLevel } from '@/lib/heatmap';
import { formatBucket } from '@/lib/timeline';

/** Height of one address's row of cells, in pixels. */
const ROW_PX = 28;

/** The chart height that gives each of `rows` addresses the same room, axis labels included. */
export function heatmapChartHeight(rows: number): number {
  return rows * ROW_PX + 32;
}

/** The fill of each band of `levels`, faintest first, and of an empty cell. */
export function heatmapColors(levels: number, dark?: boolean) {
  const colors = chartColors(dark);
  return { levels: levelColors(levels, colors.heat), empty: colors.heatEmpty };
}

interface ActivityHeatmapOptions {
  levels: readonly DensityLevel[];
  /** Widest an address gets before it is cut with an ellipsis; the tooltip and table carry it whole. */
  labelWidth: number;
  dark?: boolean;
}

/**
 * A row per address, busiest on top, and a column per timeline bucket. A cell is coloured by the
 * band its count falls in (see densityLevels); an empty cell is drawn faintly rather than left out, so the grid stays
 * whole and hovering it says so. Every cell is separated from its neighbours by a hairline of the
 * surface colour.
 */
export function activityHeatmapOption(
  heatmap: ActivityHeatmap,
  { levels, labelWidth, dark }: ActivityHeatmapOptions,
): EChartOption {
  const colors = chartColors(dark);
  const fills = heatmapColors(levels.length, dark);
  const labels = heatmap.columns.map((start) => columnLabel(start, heatmap.bucketMs));

  return {
    animationDuration: 300,
    grid: {
      left: 4,
      right: 4,
      top: 4,
      bottom: 4,
      outerBoundsMode: 'same',
      outerBoundsContain: 'axisLabel',
    },
    xAxis: {
      type: 'category',
      data: heatmap.columns.map(String),
      axisLine: { show: false },
      axisTick: { show: false },
      splitArea: { show: false },
      axisLabel: {
        color: colors.text,
        interval: (index: number) => labels[index] != null,
        formatter: (_value: string, index: number) => labels[index] ?? '',
        hideOverlap: true,
      },
    },
    yAxis: {
      type: 'category',
      inverse: true,
      data: heatmap.rows.map((row) => row.ip),
      axisLine: { show: false },
      axisTick: { show: false },
      splitArea: { show: false },
      axisLabel: {
        color: colors.ink,
        width: labelWidth,
        overflow: 'truncate',
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
      },
    },
    tooltip: {
      trigger: 'item',
      backgroundColor: colors.surface,
      borderColor: colors.grid,
      textStyle: { color: colors.ink, fontSize: 12 },
      extraCssText: 'max-width: 28rem; white-space: normal; overflow-wrap: anywhere;',
      // The address is backend text, so it is escaped into the HTML; the rest is numbers.
      formatter: (params) => {
        const item = Array.isArray(params) ? params[0] : params;
        const [x, y] = (item?.value ?? []) as number[];
        const row = heatmap.rows[y];
        const cell = row?.cells[x];
        if (!cell) return '';
        return (
          `<strong>${cell.count ? formatEvents(cell.count) : 'No events'}</strong><br/>` +
          `<span style="font-family:ui-monospace,monospace">${escapeHtml(row.ip)}</span><br/>` +
          `<span style="color:${colors.text}">${formatBucket(cell.start, heatmap.bucketMs)}</span>`
        );
      },
    },
    // The bands as ECharts colours them: a cell's count (its third value) picks the piece. The
    // legend is drawn in HTML beside the chart, so the component's own stays hidden.
    visualMap: {
      type: 'piecewise',
      show: false,
      dimension: 2,
      seriesIndex: 0,
      pieces: [
        { min: 0, max: 0, color: fills.empty },
        ...levels.map((level, i) => ({ min: level.from, max: level.to, color: fills.levels[i] })),
      ],
      outOfRange: { color: fills.empty },
    },
    series: [
      {
        type: 'heatmap',
        name: 'Events',
        itemStyle: { borderColor: colors.surface, borderWidth: 1, borderRadius: 2 },
        emphasis: { itemStyle: { borderColor: colors.ink, borderWidth: 1 } },
        data: heatmap.rows.flatMap((row, y) => row.cells.map((cell, x) => [x, y, cell.count])),
      },
    ],
  };
}
