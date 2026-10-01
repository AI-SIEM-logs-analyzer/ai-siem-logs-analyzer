import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { callsTo, json, startTestSession, stubBackend } from '@/test/backend-stub';
import { renderRoute } from '@/test/render-route';

const HOUR = 60 * 60 * 1000;
const NOW = Date.parse('2026-09-30T14:25:00Z');

const me = () => json(200, { id: 1, username: 'analyst', roles: ['ANALYST'] });
const healthy = () => json(200, { status: 'UP', checks: [] });

/** A search response counting `hourly` events per hour, as the backend facets them. */
function counts(hourly: { start: string; count: number }[]) {
  const total = hourly.reduce((sum, bucket) => sum + bucket.count, 0);
  return () =>
    json(200, {
      hits: [],
      totalHits: total,
      nextCursorOccurredAt: null,
      nextCursorEventId: null,
      facets: { bySeverity: {}, bySourceId: {}, byHost: {}, bySrcIp: {}, overTime: hourly },
    });
}

describe('dashboard event timeline', () => {
  beforeEach(() => {
    vi.useFakeTimers({ now: NOW, toFake: ['Date'] });
    startTestSession();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('asks for the hourly counts of the last 24 hours and draws them', async () => {
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /q/health': healthy,
      'GET /api/events/search': counts([
        { start: '2026-09-30T09:00:00Z', count: 1200 },
        { start: '2026-09-30T13:00:00Z', count: 34 },
      ]),
    });

    renderRoute('/');

    expect(await screen.findByText('1,234 events')).toBeInTheDocument();
    expect(screen.getByText('1,200 events')).toBeInTheDocument();
    expect(
      await screen.findByRole('img', { name: 'Column chart of events per hour, last 24 hours' }),
    ).toBeInTheDocument();

    const [request] = callsTo(fetchMock, 'GET /api/events/search');
    const query = new URL(request.url).searchParams;
    expect(query.get('from')).toBe('2026-09-29T15:00:00.000Z');
    expect(query.get('to')).toBe('2026-09-30T15:00:00.000Z');
    expect(query.get('facets')).toBe('true');
    expect(query.get('size')).toBe('1');
  });

  it('lists every bucket, empty ones included, in the table view', async () => {
    stubBackend({
      'GET /api/auth/me': me,
      'GET /q/health': healthy,
      'GET /api/events/search': counts([{ start: '2026-09-30T13:00:00Z', count: 7 }]),
    });
    const user = userEvent.setup();

    renderRoute('/');
    await user.click(await screen.findByText('Show as table'));

    const rows = within(screen.getByRole('table')).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(24);
    expect(rows.map((row) => within(row).getAllByRole('cell')[1].textContent)).toEqual([
      ...Array<string>(22).fill('0'),
      '7',
      '0',
    ]);
  });

  it('switches range from the header and keeps it in the URL', async () => {
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /q/health': healthy,
      'GET /api/events/search': counts([{ start: '2026-09-30T13:00:00Z', count: 7 }]),
    });
    const user = userEvent.setup();

    const { router } = renderRoute('/');
    await screen.findByText('Show as table');
    await user.click(
      within(screen.getByRole('group', { name: 'Time range' })).getByRole('button', {
        name: '7d',
      }),
    );

    expect(router.state.location.search).toBe('?range=7d');
    expect(await screen.findByText(/Events per 3 hours, last 7 days/)).toBeInTheDocument();
    await waitFor(() => expect(callsTo(fetchMock, 'GET /api/events/search')).toHaveLength(2));
    const query = new URL(callsTo(fetchMock, 'GET /api/events/search')[1].url).searchParams;
    expect(Date.parse(query.get('to')!) - Date.parse(query.get('from')!)).toBe(7 * 24 * HOUR);
  });

  it('reads the range from the URL', async () => {
    stubBackend({
      'GET /api/auth/me': me,
      'GET /q/health': healthy,
      'GET /api/events/search': counts([{ start: '2026-09-30T13:00:00Z', count: 7 }]),
    });

    renderRoute('/?range=30d');

    expect(await screen.findByText(/Events per 12 hours, last 30 days/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: '30d' })).toHaveAttribute('aria-pressed', 'true');
  });

  it('says so when nothing was ingested in the range', async () => {
    stubBackend({
      'GET /api/auth/me': me,
      'GET /q/health': healthy,
      'GET /api/events/search': counts([]),
    });

    renderRoute('/');

    expect(await screen.findByText(/No events in the last 24 hours/)).toBeInTheDocument();
    expect(screen.queryByRole('img')).not.toBeInTheDocument();
  });

  it('explains an unreachable search index', async () => {
    stubBackend({
      'GET /api/auth/me': me,
      'GET /q/health': healthy,
      'GET /api/events/search': () => json(503, {}),
    });

    renderRoute('/');

    expect(await screen.findByRole('alert')).toHaveTextContent('The search index is unreachable');
  });
});
