import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { callsTo, json, startTestSession, stubBackend } from '@/test/backend-stub';
import { renderRoute } from '@/test/render-route';

const HOUR = 60 * 60 * 1000;
const NOW = Date.parse('2026-09-30T14:25:00Z');

const me = () => json(200, { id: 1, username: 'analyst', roles: ['ANALYST'] });
const healthy = () => json(200, { status: 'UP', checks: [] });

type Counts = Record<string, number>;

/**
 * A search response counting `hourly` events per hour, as the backend facets them, with
 * `facets` in place of the empty term facets.
 */
function counts(
  hourly: { start: string; count: number }[],
  facets: {
    bySeverity?: Counts;
    bySrcIp?: Counts;
    byStatus?: Counts;
    topErrors?: Counts;
  } = {},
) {
  const total = hourly.reduce((sum, bucket) => sum + bucket.count, 0);
  return () =>
    json(200, {
      hits: [],
      totalHits: total,
      nextCursorOccurredAt: null,
      nextCursorEventId: null,
      facets: {
        bySeverity: {},
        bySourceId: {},
        byHost: {},
        bySrcIp: {},
        byStatus: {},
        topErrors: {},
        ...facets,
        overTime: hourly,
      },
    });
}

/** The dashboard card titled `title`. */
function card(title: string): HTMLElement {
  return screen
    .getByText(title, { selector: '[data-slot="card-title"]' })
    .closest<HTMLElement>('[data-slot="card"]')!;
}

/** The rows of the table view in `container`, as cell texts. */
async function tableRows(container: HTMLElement): Promise<string[][]> {
  await userEvent.setup().click(within(container).getByText('Show as table'));
  return within(container)
    .getAllByRole('row')
    .slice(1)
    .map((row) =>
      within(row)
        .getAllByRole('cell')
        .map((cell) => cell.textContent ?? ''),
    );
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

    // Announced once, by the timeline; the widgets say the same without repeating the alert.
    expect(await screen.findByRole('alert')).toHaveTextContent('The search index is unreachable');
    expect(screen.getAllByText(/The search index is unreachable/)).toHaveLength(4);
  });
});

describe('dashboard aggregate widgets', () => {
  const hourly = [{ start: '2026-09-30T13:00:00Z', count: 200 }];

  beforeEach(() => {
    vi.useFakeTimers({ now: NOW, toFake: ['Date'] });
    startTestSession();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("draws every widget from the timeline's one request", async () => {
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /q/health': healthy,
      'GET /api/events/search': counts(hourly, {
        bySrcIp: { '203.0.113.7': 120, '198.51.100.2': 30 },
        byStatus: { '200': 150, '404': 40, '500': 10 },
        topErrors: { 'disk failure': 8 },
        bySeverity: { INFO: 190, ERROR: 8, CRITICAL: 2 },
      }),
    });

    renderRoute('/');

    expect(
      await screen.findByRole('img', {
        name: 'Bar chart of the 2 source IPs with the most events, last 24 hours',
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('img', {
        name: 'Column chart of events per HTTP status code, last 24 hours',
      }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole('img', {
        name: 'Bar chart of the 1 most frequent error messages, last 24 hours',
      }),
    ).toBeInTheDocument();
    expect(callsTo(fetchMock, 'GET /api/events/search')).toHaveLength(1);
  });

  it('ranks the source IPs with their share of all events', async () => {
    stubBackend({
      'GET /api/auth/me': me,
      'GET /q/health': healthy,
      'GET /api/events/search': counts(hourly, {
        bySrcIp: { '198.51.100.2': 30, '203.0.113.7': 120 },
      }),
    });

    renderRoute('/');
    await screen.findByRole('img', { name: /source IPs with the most events/ });

    expect(await tableRows(card('Top source IPs'))).toEqual([
      ['203.0.113.7', '120', '60%'],
      ['198.51.100.2', '30', '15%'],
    ]);
  });

  it('splits the status codes into classes', async () => {
    stubBackend({
      'GET /api/auth/me': me,
      'GET /q/health': healthy,
      'GET /api/events/search': counts(hourly, {
        byStatus: { '404': 40, '200': 150, '500': 10 },
      }),
    });

    renderRoute('/');
    await screen.findByRole('img', { name: /HTTP status code/ });
    const status = card('Status codes');

    const classes = within(within(status).getByRole('list', { name: 'Status classes' }))
      .getAllByRole('listitem')
      .map((item) => item.textContent);
    expect(classes).toEqual([
      '2xx Success75%(150)',
      '4xx Client error20%(40)',
      '5xx Server error5%(10)',
    ]);
    expect(await tableRows(status)).toEqual([
      ['200', 'Success', '150', '75%'],
      ['404', 'Client error', '40', '20%'],
      ['500', 'Server error', '10', '5%'],
    ]);
  });

  it('lists the most frequent error messages against all error events', async () => {
    stubBackend({
      'GET /api/auth/me': me,
      'GET /q/health': healthy,
      'GET /api/events/search': counts(hourly, {
        bySeverity: { INFO: 180, ERROR: 16, CRITICAL: 4 },
        topErrors: { 'disk failure': 4, 'failed login for <admin>': 10 },
      }),
    });

    renderRoute('/');
    await screen.findByRole('img', { name: /most frequent error messages/ });
    const errors = card('Top errors');

    expect(within(errors).getByText('Error events').nextSibling).toHaveTextContent('20');
    expect(within(errors).getByText('Covered by these messages').nextSibling).toHaveTextContent(
      '70%',
    );
    expect(await tableRows(errors)).toEqual([
      ['failed login for <admin>', '10', '50%'],
      ['disk failure', '4', '20%'],
    ]);
  });

  it('says so when a facet is empty', async () => {
    stubBackend({
      'GET /api/auth/me': me,
      'GET /q/health': healthy,
      'GET /api/events/search': counts(hourly),
    });

    renderRoute('/');

    expect(
      await screen.findByText('No events with a source address in this range.'),
    ).toBeInTheDocument();
    expect(screen.getByText('No events with an HTTP status in this range.')).toBeInTheDocument();
    expect(screen.getByText('No ERROR or CRITICAL events in this range.')).toBeInTheDocument();
  });
});
