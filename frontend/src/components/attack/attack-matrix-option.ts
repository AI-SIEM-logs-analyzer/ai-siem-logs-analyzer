import { chartColors, escapeHtml } from '@/components/charts/chart-theme';
import type { EChartOption } from '@/components/charts/echart';
import type { AttackMatrix, MatrixCell } from '@/lib/attack-matrix';

export type EChartsOption = EChartOption;

const CELL_HEIGHT = 58;
const HEADER_HEIGHT = 64;
const MIN_CHART_HEIGHT = 320;

export function attackMatrixChartHeight(maxColumnDepth: number): number {
  return Math.max(MIN_CHART_HEIGHT, maxColumnDepth * CELL_HEIGHT + HEADER_HEIGHT);
}

export function attackMatrixColors(isDark: boolean) {
  if (isDark) {
    return {
      uncoveredFill: '#18181b',
      uncoveredBorder: '#27272a',
      uncoveredText: '#71717a',
      coveredFill: 'rgba(14, 165, 233, 0.14)',
      coveredBorder: 'rgba(56, 189, 248, 0.45)',
      coveredText: '#e0f2fe',
      detectedFills: ['#451a03', '#7c2d12', '#b91c1c', '#dc2626'] as [
        string,
        string,
        string,
        string,
      ],
      detectedBorders: ['#d97706', '#ea580c', '#ef4444', '#f87171'] as [
        string,
        string,
        string,
        string,
      ],
      detectedTexts: ['#fef3c7', '#ffedd5', '#fee2e2', '#ffffff'] as [
        string,
        string,
        string,
        string,
      ],
    };
  }
  return {
    uncoveredFill: '#f4f4f5',
    uncoveredBorder: '#e4e4e7',
    uncoveredText: '#71717a',
    coveredFill: '#e0f2fe',
    coveredBorder: '#38bdf8',
    coveredText: '#0c4a6e',
    detectedFills: ['#fef3c7', '#fed7aa', '#fca5a5', '#dc2626'] as [string, string, string, string],
    detectedBorders: ['#f59e0b', '#f97316', '#ef4444', '#b91c1c'] as [
      string,
      string,
      string,
      string,
    ],
    detectedTexts: ['#78350f', '#7c2d12', '#7f1d1d', '#ffffff'] as [string, string, string, string],
  };
}

function truncateName(name: string, maxLen = 18): string {
  return name.length > maxLen ? `${name.slice(0, maxLen - 1)}…` : name;
}

function cellColors(cell: MatrixCell, palette: ReturnType<typeof attackMatrixColors>) {
  if (cell.state === 'detected' && cell.level >= 1) {
    const idx = (cell.level - 1) as 0 | 1 | 2 | 3;
    return {
      fill: palette.detectedFills[idx],
      border: palette.detectedBorders[idx],
      text: palette.detectedTexts[idx],
    };
  }
  if (cell.state === 'covered') {
    return {
      fill: palette.coveredFill,
      border: palette.coveredBorder,
      text: palette.coveredText,
    };
  }
  return {
    fill: palette.uncoveredFill,
    border: palette.uncoveredBorder,
    text: palette.uncoveredText,
  };
}

export interface AttackMatrixSeriesItem {
  value: [number, number, number, number];
  cell: MatrixCell;
  itemStyle: {
    color: string;
    borderColor: string;
    borderWidth: number;
    borderRadius: number;
  };
  label: {
    color: string;
  };
}

export function attackMatrixOption(matrix: AttackMatrix, isDark: boolean): EChartsOption {
  const c = chartColors(isDark);
  const palette = attackMatrixColors(isDark);
  const rowCount = Math.max(1, matrix.maxColumnDepth);

  const data: AttackMatrixSeriesItem[] = matrix.cells.map((cell) => {
    const style = cellColors(cell, palette);
    return {
      value: [cell.tacticIndex, cell.rowIndex, cell.alertCount, cell.level],
      cell,
      itemStyle: {
        color: style.fill,
        borderColor: style.border,
        borderWidth: cell.state === 'uncovered' ? 1 : 1.5,
        borderRadius: 6,
      },
      label: {
        color: style.text,
      },
    };
  });

  return {
    animationDuration: 200,
    grid: {
      top: 48,
      right: 12,
      bottom: 12,
      left: 12,
      containLabel: false,
    },
    tooltip: {
      trigger: 'item',
      backgroundColor: c.surface,
      borderColor: c.grid,
      textStyle: { color: c.ink, fontSize: 12 },
      formatter: (params: unknown) => {
        const p = params as { data?: AttackMatrixSeriesItem };
        const cell = p.data?.cell;
        if (!cell) return '';
        const stateLabel =
          cell.state === 'detected'
            ? `Detected (${cell.alertCount} alert${cell.alertCount === 1 ? '' : 's'})`
            : cell.state === 'covered'
              ? 'Rule-covered (0 alerts)'
              : 'Uncovered';
        const sevLine = cell.highestSeverity
          ? `<div style="margin-top:2px">Highest severity: <strong>${escapeHtml(cell.highestSeverity)}</strong></div>`
          : '';
        const sourceLine =
          cell.sources.length > 0
            ? `<div style="margin-top:2px">Provenance: ${escapeHtml(cell.sources.join(', '))}</div>`
            : '';
        const subsHtml =
          cell.subTechniques.length > 0
            ? `<div style="margin-top:6px;border-top:1px solid ${c.grid};padding-top:4px">` +
              `<div style="opacity:0.75;margin-bottom:2px">Sub-techniques (${cell.subTechniques.length}):</div>` +
              cell.subTechniques
                .slice(0, 5)
                .map(
                  (sub) =>
                    `<div style="display:flex;justify-content:space-between;gap:12px">` +
                    `<span><code>${escapeHtml(sub.id)}</code> ${escapeHtml(sub.name)}</span>` +
                    `<strong>${sub.alertCount > 0 ? `${sub.alertCount} alert${sub.alertCount === 1 ? '' : 's'}` : sub.inUse ? 'covered' : '—'}</strong>` +
                    `</div>`,
                )
                .join('') +
              (cell.subTechniques.length > 5
                ? `<div style="opacity:0.6;font-size:11px;margin-top:2px">+${cell.subTechniques.length - 5} more</div>`
                : '') +
              `</div>`
            : '';

        return (
          `<div style="min-width:210px">` +
          `<div style="opacity:0.75;font-size:11px">${escapeHtml(cell.tacticName)} (${escapeHtml(cell.tacticId)})</div>` +
          `<div style="font-weight:600;margin-top:2px">${escapeHtml(cell.techniqueId)} · ${escapeHtml(cell.name)}</div>` +
          `<div style="margin-top:4px">${escapeHtml(stateLabel)}</div>` +
          sevLine +
          sourceLine +
          subsHtml +
          `</div>`
        );
      },
    },
    xAxis: {
      type: 'category',
      position: 'top',
      data: matrix.tactics.map(
        (t) => `${t.name}\n(${t.detectedTechniques}/${t.coveredTechniques})`,
      ),
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: {
        color: c.text,
        fontSize: 11,
        fontWeight: 600,
        interval: 0,
        lineHeight: 15,
      },
    },
    yAxis: {
      type: 'category',
      inverse: true,
      show: false,
      data: Array.from({ length: rowCount }, (_, i) => String(i)),
    },
    series: [
      {
        type: 'heatmap',
        data,
        label: {
          show: true,
          fontSize: 10,
          lineHeight: 13,
          formatter: (params: unknown) => {
            const p = params as { data?: AttackMatrixSeriesItem };
            const cell = p.data?.cell;
            if (!cell) return '';
            const badge = cell.alertCount > 0 ? ` [${cell.alertCount}]` : '';
            return `${cell.techniqueId}${badge}\n${truncateName(cell.name)}`;
          },
        },
        emphasis: {
          itemStyle: {
            borderColor: c.ink,
            borderWidth: 2,
          },
        },
      },
    ],
  };
}
