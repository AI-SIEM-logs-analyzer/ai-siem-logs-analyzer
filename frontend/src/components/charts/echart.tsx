import { useEffect, useRef, type CSSProperties } from 'react';
import {
  BarChart,
  HeatmapChart,
  type BarSeriesOption,
  type HeatmapSeriesOption,
} from 'echarts/charts';
import {
  GridComponent,
  TooltipComponent,
  VisualMapPiecewiseComponent,
  type GridComponentOption,
  type TooltipComponentOption,
  type VisualMapComponentOption,
} from 'echarts/components';
import * as echarts from 'echarts/core';
import { SVGRenderer } from 'echarts/renderers';

// Apache ECharts, tree-shaken: only the chart types and components registered here end up in
// the bundle. Add a series type or component to `use` (and to EChartOption) when a chart needs
// it. The SVG renderer keeps lines crisp at any zoom and the DOM inspectable.
echarts.use([
  BarChart,
  HeatmapChart,
  GridComponent,
  TooltipComponent,
  VisualMapPiecewiseComponent,
  SVGRenderer,
]);

export type EChartOption = echarts.ComposeOption<
  | BarSeriesOption
  | HeatmapSeriesOption
  | GridComponentOption
  | TooltipComponentOption
  | VisualMapComponentOption
>;

/** What a click on a mark reports: its series, data index and value. */
export type EChartClick = echarts.ECElementEvent;

interface EChartProps {
  option: EChartOption;
  /** What the chart shows, for screen readers; pair it with a table view of the same data. */
  label: string;
  className?: string;
  /** For a size that follows the data, such as a height per bar. */
  style?: CSSProperties;
  /** Called with the mark clicked; pair it with a keyboard path to the same place. */
  onClick?: (event: EChartClick) => void;
}

/** One ECharts instance bound to a div, re-drawn when `option` changes and resized with it. */
export function EChart({ option, label, className, style, onClick }: EChartProps) {
  const container = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);
  // The latest handler, so a new closure each render does not rebind the chart's listener.
  const clickHandler = useRef(onClick);

  useEffect(() => {
    clickHandler.current = onClick;
  }, [onClick]);

  useEffect(() => {
    const element = container.current!;
    const instance = echarts.init(element, null, { renderer: 'svg' });
    chart.current = instance;
    instance.on('click', (event) => clickHandler.current?.(event));
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
