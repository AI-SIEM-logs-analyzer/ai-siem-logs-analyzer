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

export type EChartClick = echarts.ECElementEvent;

interface EChartProps {
  option: EChartOption;

  label?: string;
  ariaLabel?: string;
  height?: number;
  className?: string;

  style?: CSSProperties;

  onClick?: (event: EChartClick) => void;
  onCellClick?: (coords: { colIndex: number; rowIndex: number }) => void;
}

export function EChart({
  option,
  label,
  ariaLabel,
  height,
  className,
  style,
  onClick,
  onCellClick,
}: EChartProps) {
  const container = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);

  const clickHandler = useRef(onClick);
  const cellClickHandler = useRef(onCellClick);

  useEffect(() => {
    clickHandler.current = onClick;
    cellClickHandler.current = onCellClick;
  }, [onClick, onCellClick]);

  useEffect(() => {
    const element = container.current!;
    const instance = echarts.init(element, null, { renderer: 'svg' });
    chart.current = instance;
    instance.on('click', (event) => {
      clickHandler.current?.(event);
      if (cellClickHandler.current && Array.isArray(event.value)) {
        const [colIndex, rowIndex] = event.value as number[];
        if (typeof colIndex === 'number' && typeof rowIndex === 'number') {
          cellClickHandler.current({ colIndex, rowIndex });
        }
      }
    });
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
    chart.current?.setOption(option, { notMerge: true });
  }, [option]);

  const mergedStyle = height !== undefined ? { height, ...style } : style;

  return (
    <div
      ref={container}
      role="img"
      aria-label={label ?? ariaLabel}
      className={className}
      style={mergedStyle}
    />
  );
}
