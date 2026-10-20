import { describe, expect, it } from 'vitest';
import { buildAttackMatrix } from '@/lib/attack-matrix';
import {
  attackMatrixChartHeight,
  attackMatrixColors,
  attackMatrixOption,
} from '@/components/attack/attack-matrix-option';

const MATRIX = buildAttackMatrix(
  [
    { id: 'TA0001', shortName: 'initial-access', name: 'Initial Access', matrixOrder: 1 },
    { id: 'TA0006', shortName: 'credential-access', name: 'Credential Access', matrixOrder: 6 },
  ],
  [
    {
      id: 'T1190',
      name: 'Exploit Public-Facing Application',
      subTechnique: false,
      inUse: true,
      deprecated: false,
      revoked: false,
      platforms: [],
      tactics: [{ id: 'TA0001', shortName: 'initial-access', name: 'Initial Access' }],
    },
    {
      id: 'T1110',
      name: 'Brute Force <script>',
      subTechnique: false,
      inUse: true,
      deprecated: false,
      revoked: false,
      platforms: [],
      tactics: [{ id: 'TA0006', shortName: 'credential-access', name: 'Credential Access' }],
    },
  ],
  [
    {
      id: 'a1',
      title: 'SSH Brute Force',
      severity: 'HIGH',
      status: 'NEW',
      createdAt: '2026-04-12T10:00:00Z',
      eventCount: 4,
      techniques: [
        {
          id: 'T1110.001',
          name: 'Password Guessing',
          source: 'RULE',
          tactics: [{ id: 'TA0006', shortName: 'credential-access', name: 'Credential Access' }],
        },
      ],
    },
  ],
  'active',
);

describe('attackMatrixOption', () => {
  it('computes chart height bounded by minimum height', () => {
    expect(attackMatrixChartHeight(0)).toBe(320);
    expect(attackMatrixChartHeight(8)).toBe(8 * 58 + 64);
  });

  it('builds a heatmap series with distinct colors for covered vs detected cells and escapes tooltip HTML', () => {
    const option = attackMatrixOption(MATRIX, false);
    const palette = attackMatrixColors(false);

    const series = (option.series as unknown[])[0] as {
      type: string;
      data: Array<{
        value: [number, number, number, number];
        itemStyle: { color: string };
        cell: { techniqueId: string };
      }>;
    };
    expect(series.type).toBe('heatmap');
    expect(series.data).toHaveLength(2);

    const coveredItem = series.data.find((d) => d.cell.techniqueId === 'T1190')!;
    const detectedItem = series.data.find((d) => d.cell.techniqueId === 'T1110')!;
    expect(coveredItem.itemStyle.color).toBe(palette.coveredFill);
    expect(detectedItem.itemStyle.color).toBe(palette.detectedFills[3]);

    const tooltip = option.tooltip as { formatter: (params: unknown) => string };
    const html = tooltip.formatter({ data: detectedItem });
    expect(html).toContain('T1110');
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('T1110.001');
  });

  // ECharts refuses to render a cartesian heatmap without a visualMap ("Heatmap must use with
  // visualMap"), so the matrix needs one, and it has to paint each cell its own fill.
  it('declares a visualMap that paints every cell its own fill', () => {
    const option = attackMatrixOption(MATRIX, false);
    const visualMap = option.visualMap as {
      type: string;
      show: boolean;
      dimension: number;
      pieces: Array<{ value: number; color: string }>;
    };
    expect(visualMap).toMatchObject({ type: 'piecewise', show: false, dimension: 4 });

    const series = (option.series as unknown[])[0] as {
      data: Array<{ value: number[]; itemStyle: { color: string } }>;
    };
    for (const item of series.data) {
      const piece = visualMap.pieces.find((p) => p.value === item.value[4]);
      expect(piece?.color).toBe(item.itemStyle.color);
    }
  });
});
