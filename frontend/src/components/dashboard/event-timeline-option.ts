import { chartColors, count, formatEvents } from '@/components/charts/chart-theme';
import type { EChartOption } from '@/components/charts/echart';
import { formatBucket, peakBucket, type TimelineBucket, type TimelineWindow } from '@/lib/timeline';

/**
 * A column per bucket on a time axis spanning the whole window, so an empty stretch reads as
 * quiet rather than as missing. Only the peak carries a value label; the axis, the tooltip and
 * the table view carry the rest.
 */
export function eventTimelineOption(
  buckets: readonly TimelineBucket[],
  window: TimelineWindow,
  dark?: boolean,
): EChartOption {
  const colors = chartColors(dark);
  const peak = peakBucket(buckets);
  const middle = window.bucketMs / 2;

  return {
    animationDuration: 300,
    grid: {
      left: 4,
      right: 12,
      top: 24,
      bottom: 4,
      outerBoundsMode: 'same',
      outerBoundsContain: 'axisLabel',
    },
    xAxis: {
      type: 'time',
      min: window.from,
      max: window.to,
      axisLine: { lineStyle: { color: colors.grid } },
      axisTick: { show: false },
      axisLabel: { color: colors.text, hideOverlap: true },
      splitLine: { show: false },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLabel: { color: colors.text, formatter: (value: number) => count.format(value) },
      splitLine: { lineStyle: { color: colors.grid, width: 1, type: 'solid' } },
    },
    tooltip: {
      trigger: 'axis',
      axisPointer: { type: 'line', snap: true, lineStyle: { color: colors.pointer } },
      backgroundColor: colors.surface,
      borderColor: colors.grid,
      textStyle: { color: colors.ink, fontSize: 12 },
      // Built from numbers and dates only, so the HTML carries nothing from the backend.
      formatter: (params) => {
        const item = Array.isArray(params) ? params[0] : params;
        const bucket = buckets[item?.dataIndex ?? -1];
        if (!bucket) return '';
        return (
          `<strong>${formatEvents(bucket.count)}</strong><br/>` +
          `<span style="color:${colors.text}">${formatBucket(bucket.start, window.bucketMs)}</span>`
        );
      },
    },
    series: [
      {
        type: 'bar',
        name: 'Events',
        barMaxWidth: 24,
        itemStyle: { color: colors.bar, borderRadius: [4, 4, 0, 0] },
        emphasis: { itemStyle: { color: colors.barHover } },
        data: buckets.map((bucket) => ({
          value: [bucket.start + middle, bucket.count],
          label:
            bucket === peak
              ? {
                  show: true,
                  position: 'top',
                  color: colors.text,
                  formatter: count.format(bucket.count),
                }
              : undefined,
        })),
      },
    ],
  };
}
