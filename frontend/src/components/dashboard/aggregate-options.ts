import {
  chartColors,
  count,
  escapeHtml,
  formatEvents,
  STATUS_COLORS,
} from '@/components/charts/chart-theme';
import type { EChartOption } from '@/components/charts/echart';
import {
  STATUS_CLASSES,
  type RankedEntry,
  type StatusClass,
  type StatusCodeCount,
} from '@/lib/facets';

/** Height of one row of a ranked bar chart, bar and gap, in pixels; taller with its label above. */
const RANKED_ROW_PX = { beside: 32, above: 44 } as const;

/** The chart height that gives each of `rows` bars the same room, whatever their number. */
export function rankedChartHeight(rows: number, labelsAbove = false): number {
  return rows * RANKED_ROW_PX[labelsAbove ? 'above' : 'beside'] + 8;
}

interface RankedBarOptions {
  /**
   * Widest a category label gets before it is cut with an ellipsis; the tooltip and the table
   * carry the whole value.
   */
  labelWidth: number;
  /**
   * Each label on its own line above its bar rather than beside it, for long text (a log
   * message): the bars keep the whole width, however narrow the card.
   */
  labelsAbove?: boolean;
  /** Monospace labels, for addresses. */
  mono?: boolean;
  dark?: boolean;
}

/**
 * Horizontal bars, largest on top. Every bar carries its count at its end, so the value axis
 * is left out; with at most ten bars that is a label per row rather than clutter.
 */
export function rankedBarOption(
  entries: readonly RankedEntry[],
  { labelWidth, labelsAbove = false, mono = false, dark }: RankedBarOptions,
): EChartOption {
  const colors = chartColors(dark);

  return {
    animationDuration: 300,
    grid: {
      left: labelsAbove ? 0 : 4,
      right: 56,
      top: 4,
      bottom: 4,
      outerBoundsMode: 'same',
      outerBoundsContain: 'axisLabel',
    },
    xAxis: { type: 'value', show: false },
    yAxis: {
      type: 'category',
      inverse: true,
      data: entries.map((entry) => entry.key),
      axisLine: { show: !labelsAbove, lineStyle: { color: colors.grid } },
      axisTick: { show: false },
      axisLabel: {
        color: colors.ink,
        width: labelWidth,
        overflow: 'truncate',
        fontFamily: mono ? 'ui-monospace, SFMono-Regular, Menlo, monospace' : undefined,
        // Inside the grid, left-aligned and lifted off the centre of the row onto the bar's top.
        ...(labelsAbove && {
          inside: true,
          align: 'left',
          verticalAlign: 'bottom',
          margin: 0,
          padding: [0, 0, 9, 0],
        }),
      },
    },
    tooltip: {
      trigger: 'item',
      backgroundColor: colors.surface,
      borderColor: colors.grid,
      textStyle: { color: colors.ink, fontSize: 12 },
      extraCssText: 'max-width: 28rem; white-space: normal; overflow-wrap: anywhere;',
      // The key is backend text (an address, a log message), so it is escaped into the HTML.
      formatter: (params) => {
        const item = Array.isArray(params) ? params[0] : params;
        const entry = entries[item?.dataIndex ?? -1];
        if (!entry) return '';
        return (
          `<strong>${formatEvents(entry.count)}</strong><br/>` +
          `<span style="color:${colors.text}">${escapeHtml(entry.key)}</span>`
        );
      },
    },
    series: [
      {
        type: 'bar',
        name: 'Events',
        barMaxWidth: labelsAbove ? 12 : 20,
        itemStyle: { color: colors.bar, borderRadius: [0, 4, 4, 0] },
        emphasis: { itemStyle: { color: colors.barHover } },
        label: {
          show: true,
          position: 'right',
          color: colors.text,
          formatter: (params) => count.format(Number(params.value)),
        },
        data: entries.map((entry) => entry.count),
      },
    ],
  };
}

/** Each class's colour: success good, redirection informational, the error classes alarming. */
export const STATUS_CLASS_COLORS: Record<StatusClass, string> = {
  '1xx': STATUS_COLORS.neutral,
  '2xx': STATUS_COLORS.good,
  '3xx': STATUS_COLORS.info,
  '4xx': STATUS_COLORS.warning,
  '5xx': STATUS_COLORS.critical,
};

/**
 * A column per status code, in numeric order and coloured by its class. The legend above the
 * chart names each colour with its class, so colour never carries the class alone; the code
 * itself is on the axis.
 */
export function statusCodesOption(codes: readonly StatusCodeCount[], dark?: boolean): EChartOption {
  const colors = chartColors(dark);

  return {
    animationDuration: 300,
    grid: {
      left: 4,
      right: 12,
      top: 12,
      bottom: 4,
      outerBoundsMode: 'same',
      outerBoundsContain: 'axisLabel',
    },
    xAxis: {
      type: 'category',
      data: codes.map((code) => String(code.code)),
      axisLine: { lineStyle: { color: colors.grid } },
      axisTick: { show: false },
      axisLabel: { color: colors.text, hideOverlap: true },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: colors.text, formatter: (value: number) => count.format(value) },
      splitLine: { lineStyle: { color: colors.grid, width: 1, type: 'solid' } },
    },
    tooltip: {
      trigger: 'item',
      backgroundColor: colors.surface,
      borderColor: colors.grid,
      textStyle: { color: colors.ink, fontSize: 12 },
      // Built from numbers and the fixed class names only.
      formatter: (params) => {
        const item = Array.isArray(params) ? params[0] : params;
        const code = codes[item?.dataIndex ?? -1];
        if (!code) return '';
        return (
          `<strong>${code.code}</strong> · ${formatEvents(code.count)}<br/>` +
          `<span style="color:${colors.text}">${STATUS_CLASSES[code.statusClass]}</span>`
        );
      },
    },
    series: [
      {
        type: 'bar',
        name: 'Events',
        barMaxWidth: 32,
        data: codes.map((code) => ({
          value: code.count,
          itemStyle: { color: STATUS_CLASS_COLORS[code.statusClass], borderRadius: [4, 4, 0, 0] },
        })),
      },
    ],
  };
}
