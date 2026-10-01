import {
  rankedBarOption,
  STATUS_CLASS_COLORS,
  statusCodesOption,
} from '@/components/dashboard/aggregate-options';
import { statusBreakdown } from '@/lib/facets';

type Formatter = (params: { dataIndex: number }) => string;

function tooltipOf(option: ReturnType<typeof rankedBarOption>): Formatter {
  const tooltip = option.tooltip as { formatter: Formatter };
  return tooltip.formatter;
}

describe('rankedBarOption', () => {
  it('draws the entries top down, in the order given', () => {
    const option = rankedBarOption(
      [
        { key: '203.0.113.7', count: 40 },
        { key: '198.51.100.2', count: 12 },
      ],
      { labelWidth: 120, dark: false },
    );

    expect(option.yAxis).toMatchObject({
      type: 'category',
      inverse: true,
      data: ['203.0.113.7', '198.51.100.2'],
    });
    expect(option.series).toMatchObject([{ type: 'bar', data: [40, 12] }]);
  });

  it('escapes backend text in the tooltip', () => {
    const option = rankedBarOption([{ key: '<img src=x onerror=alert(1)>', count: 2 }], {
      labelWidth: 200,
      dark: false,
    });

    const html = tooltipOf(option)({ dataIndex: 0 });

    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(html).not.toContain('<img');
    expect(html).toContain('2 events');
  });
});

describe('statusCodesOption', () => {
  it('colours each column by its class', () => {
    const { codes } = statusBreakdown({ '200': 5, '404': 2, '502': 1 });

    const option = statusCodesOption(codes, false);

    expect(option.xAxis).toMatchObject({ data: ['200', '404', '502'] });
    expect(option.series).toMatchObject([
      {
        data: [
          { value: 5, itemStyle: { color: STATUS_CLASS_COLORS['2xx'] } },
          { value: 2, itemStyle: { color: STATUS_CLASS_COLORS['4xx'] } },
          { value: 1, itemStyle: { color: STATUS_CLASS_COLORS['5xx'] } },
        ],
      },
    ]);
  });
});
