import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { apiClient } from '@/api/client';
import { startTestSession } from '@/test/backend-stub';
import { renderRoute } from '@/test/render-route';

vi.mock('@/components/charts/lazy-echart', () => ({
  LazyEChart: ({
    option,
    onCellClick,
    ariaLabel,
  }: {
    option: {
      series?: Array<{
        data?: Array<{
          value: [number, number, number, number];
          cell: { techniqueId: string; name: string };
        }>;
      }>;
    };
    onCellClick?: (coords: { colIndex: number; rowIndex: number }) => void;
    ariaLabel?: string;
  }) => {
    const items = option.series?.[0]?.data ?? [];
    return (
      <div role="img" aria-label={ariaLabel}>
        {items.map((item) => (
          <button
            key={`${item.value[0]}-${item.value[1]}-${item.cell.techniqueId}`}
            type="button"
            data-testid={`matrix-cell-${item.cell.techniqueId}`}
            onClick={() => onCellClick?.({ colIndex: item.value[0], rowIndex: item.value[1] })}
          >
            {item.cell.techniqueId} ({item.value[2]})
          </button>
        ))}
      </div>
    );
  },
}));

function mockAttackApis() {
  startTestSession();
  return vi.spyOn(apiClient, 'GET').mockImplementation(((url: string, init?: unknown) => {
    if (url === '/api/auth/me') {
      return Promise.resolve({
        data: {
          id: 'u1',
          username: 'alice',
          email: 'a@x.io',
          role: 'ANALYST',
          active: true,
          createdAt: '2026-04-01T00:00:00Z',
        },
        error: undefined,
        response: new Response(),
      });
    }
    if (url === '/api/attack/dataset') {
      return Promise.resolve({
        data: {
          version: '19.2',
          domain: 'enterprise-attack',
          tacticCount: 2,
          techniqueCount: 3,
          importedAt: '2026-04-12T00:00:00Z',
          source: 'bundled',
        },
        error: undefined,
        response: new Response(),
      });
    }
    if (url === '/api/attack/tactics') {
      return Promise.resolve({
        data: [
          { id: 'TA0001', shortName: 'initial-access', name: 'Initial Access', matrixOrder: 1 },
          {
            id: 'TA0006',
            shortName: 'credential-access',
            name: 'Credential Access',
            matrixOrder: 6,
          },
        ],
        error: undefined,
        response: new Response(),
      });
    }
    if (url === '/api/attack/techniques') {
      const all = [
        {
          id: 'T1190',
          name: 'Exploit Public-Facing Application',
          subTechnique: false,
          inUse: true,
          deprecated: false,
          revoked: false,
          platforms: ['Linux'],
          tactics: [{ id: 'TA0001', shortName: 'initial-access', name: 'Initial Access' }],
        },
        {
          id: 'T1110',
          name: 'Brute Force',
          subTechnique: false,
          inUse: true,
          deprecated: false,
          revoked: false,
          platforms: ['Linux'],
          tactics: [{ id: 'TA0006', shortName: 'credential-access', name: 'Credential Access' }],
        },
        {
          id: 'T1555',
          name: 'Credentials from Password Stores',
          subTechnique: false,
          inUse: false,
          deprecated: false,
          revoked: false,
          platforms: ['Linux'],
          tactics: [{ id: 'TA0006', shortName: 'credential-access', name: 'Credential Access' }],
        },
      ];
      const inUse = (init as { params?: { query?: { inUse?: boolean } } } | undefined)?.params
        ?.query?.inUse;
      return Promise.resolve({
        data: inUse ? all.filter((t) => t.inUse) : all,
        error: undefined,
        response: new Response(),
      });
    }
    if (url === '/api/alerts') {
      return Promise.resolve({
        data: {
          items: [
            {
              id: 'alert-1',
              title: 'SSH Brute Force',
              severity: 'HIGH',
              status: 'NEW',
              createdAt: '2026-04-12T10:00:00Z',
              eventCount: 5,
              techniques: [
                {
                  id: 'T1110',
                  name: 'Brute Force',
                  source: 'RULE',
                  tactics: [
                    { id: 'TA0006', shortName: 'credential-access', name: 'Credential Access' },
                  ],
                },
              ],
            },
          ],
          page: 0,
          size: 100,
          totalElements: 1,
          totalPages: 1,
        },
        error: undefined,
        response: new Response(),
      });
    }
    return Promise.reject(new Error(`Unexpected GET ${url}`));
  }) as never);
}

describe('AttackMatrixPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders covered and detected techniques by default and toggles to full Enterprise matrix', async () => {
    mockAttackApis();
    const user = userEvent.setup();
    renderRoute('/attack');

    expect(await screen.findByText(/MITRE ATT&CK Navigator/i)).toBeInTheDocument();
    expect(await screen.findByTestId('matrix-cell-T1110')).toHaveTextContent('T1110 (1)');
    expect(screen.getByTestId('matrix-cell-T1190')).toHaveTextContent('T1190 (0)');
    expect(screen.queryByTestId('matrix-cell-T1555')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /Full Enterprise matrix/i }));
    expect(await screen.findByTestId('matrix-cell-T1555')).toHaveTextContent('T1555 (0)');
  });

  it('navigates to /alerts filtered by technique and tactic when a cell is clicked', async () => {
    mockAttackApis();
    const user = userEvent.setup();
    const { router } = renderRoute('/attack?severity=HIGH');

    const cell = await screen.findByTestId('matrix-cell-T1110');
    await user.click(cell);

    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /Alerts/i, level: 1 })).toBeInTheDocument();
    });
    expect(router.state.location.pathname).toBe('/alerts');
    const search = new URLSearchParams(router.state.location.search);
    expect(search.getAll('technique')).toEqual(['T1110']);
    expect(search.getAll('tactic')).toEqual(['TA0006']);
    expect(search.getAll('severity')).toEqual(['HIGH']);
  });
});
