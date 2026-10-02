import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { callsTo, json, startTestSession, stubBackend } from '@/test/backend-stub';
import { renderRoute } from '@/test/render-route';

const NOW = Date.parse('2026-09-30T14:25:00Z');

const me = () => json(200, { id: 1, username: 'analyst', roles: ['ANALYST'] });

const hits = [
  {
    eventId: 101,
    sourceId: 3,
    occurredAt: '2026-09-30T14:20:00Z',
    ingestedAt: '2026-09-30T14:20:02Z',
    severity: 'ERROR',
    message: 'GET /wp-login.php 503',
    raw: '203.0.113.7 - - [30/Sep/2026:14:20:00 +0000] "GET /wp-login.php HTTP/1.1" 503 512',
    fields: {
      host: 'web-1',
      srcIp: '203.0.113.7',
      method: 'GET',
      path: '/wp-login.php',
      status: 503,
      geoCountryName: 'Netherlands',
      uaBot: true,
    },
  },
  {
    eventId: 100,
    sourceId: 3,
    occurredAt: '2026-09-30T14:10:00Z',
    ingestedAt: '2026-09-30T14:10:01Z',
    severity: 'INFO',
    message: 'Accepted password for root',
    raw: 'Sep 30 14:10:00 bastion sshd[42]: Accepted password for root',
    fields: { host: 'bastion', srcIp: '198.51.100.4' },
  },
];

function page(
  pageHits: unknown[],
  totalHits: number,
  next: { occurredAt: string; eventId: number } | null = null,
) {
  return json(200, {
    hits: pageHits,
    totalHits,
    nextCursorOccurredAt: next?.occurredAt ?? null,
    nextCursorEventId: next?.eventId ?? null,
  });
}

/** The query of the `n`th search the stub received. */
function searchQuery(fetchMock: ReturnType<typeof stubBackend>, n: number): URLSearchParams {
  return new URL(callsTo(fetchMock, 'GET /api/events/search')[n].url).searchParams;
}

function resultRows(): HTMLElement[] {
  return within(screen.getByRole('table')).getAllByRole('row').slice(1);
}

describe('events page', () => {
  beforeEach(() => {
    vi.useFakeTimers({ now: NOW, toFake: ['Date'] });
    startTestSession();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('searches the last 24 hours, newest first, and lists the hits', async () => {
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /api/events/search': () => page(hits, 2),
    });

    renderRoute('/events');

    expect(await screen.findByText('GET /wp-login.php 503')).toBeInTheDocument();
    expect(screen.getByText('2 events · page 1 of 1')).toBeInTheDocument();
    expect(resultRows()).toHaveLength(2);

    const query = searchQuery(fetchMock, 0);
    expect(query.get('from')).toBe('2026-09-29T14:25:00.000Z');
    expect(query.get('to')).toBe('2026-09-30T14:25:00.000Z');
    expect(query.get('order')).toBe('desc');
    expect(query.get('size')).toBe('50');
  });

  it('opens every field of an event on click', async () => {
    stubBackend({
      'GET /api/auth/me': me,
      'GET /api/events/search': () => page(hits, 2),
    });
    const user = userEvent.setup();

    renderRoute('/events');
    await user.click(await screen.findByText('GET /wp-login.php 503'));

    const panel = await screen.findByRole('dialog');
    expect(within(panel).getByText('Event #101')).toBeInTheDocument();
    expect(within(panel).getByText('Netherlands')).toBeInTheDocument();
    expect(within(panel).getByText('/wp-login.php')).toBeInTheDocument();
    expect(within(panel).getByText(hits[0].raw)).toBeInTheDocument();
    expect(within(panel).getByRole('button', { name: 'Previous event' })).toBeDisabled();

    await user.click(within(panel).getByRole('button', { name: 'Next event' }));
    expect(within(panel).getByText('Event #100')).toBeInTheDocument();
    expect(within(panel).getByText('Accepted password for root', { selector: 'p' })).toBeVisible();

    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('opens an event from the keyboard', async () => {
    stubBackend({
      'GET /api/auth/me': me,
      'GET /api/events/search': () => page(hits, 2),
    });
    const user = userEvent.setup();

    renderRoute('/events');
    await screen.findByText('GET /wp-login.php 503');
    resultRows()[1].focus();
    await user.keyboard('{Enter}');

    expect(within(await screen.findByRole('dialog')).getByText('Event #100')).toBeInTheDocument();
  });

  it('drills down from a value in the table and keeps the filter in the URL', async () => {
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /api/events/search': (request) =>
        new URL(request.url).searchParams.get('srcIp') ? page([hits[0]], 1) : page(hits, 2),
    });
    const user = userEvent.setup();

    const { router } = renderRoute('/events');
    await screen.findByText('GET /wp-login.php 503');
    await user.click(screen.getByRole('button', { name: 'Filter by 203.0.113.7' }));

    expect(await screen.findByText('1 event · page 1 of 1')).toBeInTheDocument();
    expect(searchQuery(fetchMock, 1).getAll('srcIp')).toEqual(['203.0.113.7']);
    expect(router.state.location.search).toBe('?srcIp=203.0.113.7');
    // The click narrowed the search; it did not open the event.
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

    const active = screen.getByRole('list', { name: 'Active filters' });
    await user.click(within(active).getByRole('button', { name: 'Remove filter IP 203.0.113.7' }));
    expect(await screen.findByText('2 events · page 1 of 1')).toBeInTheDocument();
    expect(router.state.location.search).toBe('');
  });

  it('drills down from the details panel', async () => {
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /api/events/search': () => page(hits, 2),
    });
    const user = userEvent.setup();

    const { router } = renderRoute('/events');
    await user.click(await screen.findByText('GET /wp-login.php 503'));
    const panel = await screen.findByRole('dialog');
    await user.click(within(panel).getByRole('button', { name: 'Filter by status 503' }));

    await waitFor(() => expect(searchQuery(fetchMock, 1).getAll('status')).toEqual(['503']));
    expect(router.state.location.search).toBe('?status=503');
    expect(within(panel).getByRole('button', { name: 'Filter by status 503' })).toBeDisabled();
  });

  it('applies the filter form and the severity toggles', async () => {
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /api/events/search': () => page(hits, 2),
    });
    const user = userEvent.setup();

    renderRoute('/events');
    await screen.findByText('GET /wp-login.php 503');

    await user.type(screen.getByLabelText('Search messages'), 'wp-login');
    await user.type(screen.getByLabelText('HTTP status'), '5xx, 404');
    await user.click(screen.getByRole('button', { name: 'Apply' }));
    await waitFor(() => expect(callsTo(fetchMock, 'GET /api/events/search')).toHaveLength(2));
    expect(searchQuery(fetchMock, 1).get('q')).toBe('wp-login');
    expect(searchQuery(fetchMock, 1).getAll('status')).toEqual(['5xx', '404']);

    const severities = screen.getByRole('group', { name: 'Severity' });
    await user.click(within(severities).getByRole('button', { name: /CRITICAL/ }));
    await waitFor(() => expect(callsTo(fetchMock, 'GET /api/events/search')).toHaveLength(3));
    expect(searchQuery(fetchMock, 2).getAll('severity')).toEqual(['CRITICAL']);
    expect(searchQuery(fetchMock, 2).get('q')).toBe('wp-login');

    await user.selectOptions(screen.getByLabelText('Time range'), 'all');
    await waitFor(() => expect(callsTo(fetchMock, 'GET /api/events/search')).toHaveLength(4));
    expect(searchQuery(fetchMock, 3).has('from')).toBe(false);
  });

  it('refuses a status that is not a code before asking the backend', async () => {
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /api/events/search': () => page(hits, 2),
    });
    const user = userEvent.setup();

    renderRoute('/events');
    await screen.findByText('GET /wp-login.php 503');
    await user.type(screen.getByLabelText('HTTP status'), 'teapot');
    await user.click(screen.getByRole('button', { name: 'Apply' }));

    expect(screen.getByRole('alert')).toHaveTextContent('teapot: a status is a code');
    expect(callsTo(fetchMock, 'GET /api/events/search')).toHaveLength(1);
  });

  it('sorts oldest first from the time column', async () => {
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /api/events/search': () => page(hits, 2),
    });
    const user = userEvent.setup();

    const { router } = renderRoute('/events');
    await screen.findByText('GET /wp-login.php 503');
    await user.click(screen.getByRole('button', { name: 'Time' }));

    await waitFor(() => expect(searchQuery(fetchMock, 1).get('order')).toBe('asc'));
    expect(router.state.location.search).toBe('?order=asc');
    expect(screen.getByRole('columnheader', { name: 'Time' })).toHaveAttribute(
      'aria-sort',
      'ascending',
    );
  });

  it('pages by cursor, with the same window on every page', async () => {
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /api/events/search': (request) =>
        new URL(request.url).searchParams.has('cursorEventId')
          ? page([hits[1]], 51)
          : page([hits[0]], 51, { occurredAt: '2026-09-30T14:20:00Z', eventId: 101 }),
    });
    const user = userEvent.setup();

    renderRoute('/events');
    expect(await screen.findByText('51 events · page 1 of 2')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Previous' })).toBeDisabled();

    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(await screen.findByText('51 events · page 2 of 2')).toBeInTheDocument();
    expect(screen.getByText('Accepted password for root')).toBeInTheDocument();
    const second = searchQuery(fetchMock, 1);
    expect(second.get('cursorOccurredAt')).toBe('2026-09-30T14:20:00Z');
    expect(second.get('cursorEventId')).toBe('101');
    expect(second.get('from')).toBe(searchQuery(fetchMock, 0).get('from'));
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();

    await user.click(screen.getByRole('button', { name: 'Previous' }));
    expect(await screen.findByText('51 events · page 1 of 2')).toBeInTheDocument();
  });

  it('says so when nothing matches, and when the index is down', async () => {
    let down = false;
    stubBackend({
      'GET /api/auth/me': me,
      'GET /api/events/search': () => (down ? json(503, {}) : page([], 0)),
    });
    const user = userEvent.setup();

    renderRoute('/events?severity=CRITICAL');
    expect(await screen.findByText('No events match these filters.')).toBeInTheDocument();

    down = true;
    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('The search index is unreachable');
  });
});
