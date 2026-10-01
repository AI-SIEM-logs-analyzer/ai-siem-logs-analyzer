import { useEffect, useRef, type CSSProperties } from 'react';
import { BarChart, type BarSeriesOption } from 'echarts/charts';
import {
  GridComponent,
  TooltipComponent,
  type GridComponentOption,
  type TooltipComponentOption,
} from 'echarts/components';
import * as echarts from 'echarts/core';
import { SVGRenderer } from 'echarts/renderers';

// Apache ECharts, tree-shaken: only the chart types and components registered here end up in
// the bundle. Add a series type or component to `use` (and to EChartOption) when a chart needs
// it. The SVG renderer keeps lines crisp at any zoom and the DOM inspectable.
echarts.use([BarChart, GridComponent, TooltipComponent, SVGRenderer]);

export type EChartOption = echarts.ComposeOption<
  BarSeriesOption | GridComponentOption | TooltipComponentOption
>;

interface EChartProps {
  option: EChartOption;
  /** What the chart shows, for screen readers; pair it with a table view of the same data. */
  label: string;
  className?: string;
  /** For a size that follows the data, such as a height per bar. */
  style?: CSSProperties;
}

/** One ECharts instance bound to a div, re-drawn when `option` changes and resized with it. */
export function EChart({ option, label, className, style }: EChartProps) {
  const container = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);

  useEffect(() => {
    const element = container.current!;
    const instance = echarts.init(element, null, { renderer: 'svg' });
    chart.current = instance;
    const observer =
      typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(() => instance.resize());
    observer?.observe(element);
    return () => {
      observer?.disconnect();
      instance.dispose();
      chart.current = null;
    };
  }, []);

  useEffect(() => {
    // notMerge: the option is the whole chart, so a bucket that is gone does not linger.
    chart.current?.setOption(option, { notMerge: true });
  }, [option]);

  return <div ref={container} role="img" aria-label={label} className={className} style={style} />;
}
