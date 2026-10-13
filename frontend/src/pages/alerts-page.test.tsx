import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { callsTo, json, startTestSession, stubBackend } from '@/test/backend-stub';
import { renderRoute } from '@/test/render-route';

const me = () => json(200, { id: 1, username: 'viewer', roles: ['VIEWER'] });
const analyst = () => json(200, { id: 2, username: 'triage', roles: ['ANALYST'] });

const aiSummary = {
  severity: 'ERROR',
  attackType: 'BRUTE_FORCE',
  summary: 'Six failed logins from 10.0.0.7 within a minute.',
  recommendedAction: 'Block 10.0.0.7 and check the targeted account.',
  model: 'anthropic/claude-opus-5-5',
  summarizedAt: '2026-10-01T10:05:00Z',
};

const bruteForce = {
  id: 12,
  title: 'brute-force-login',
  detail: 'count = 6 (>= 5) within 1m for srcIp=10.0.0.7',
  severity: 'CRITICAL',
  status: 'NEW',
  raisedAt: '2026-10-01T10:00:06Z',
  statusChangedAt: '2026-10-01T10:00:06Z',
  ruleId: 4,
  ruleName: 'brute-force-login',
  groupKey: { srcIp: '10.0.0.7' },
  aggregateValue: 6,
  eventCount: 6,
  windowStart: '2026-10-01T10:00:00Z',
  windowEnd: '2026-10-01T10:00:05Z',
  trigger: {
    eventId: 41,
    sourceId: 3,
    sourceName: 'web-1',
    occurredAt: '2026-10-01T10:00:05Z',
    ingestedAt: '2026-10-01T10:00:06Z',
    severity: 'WARNING',
    message: 'POST /login 401',
    raw: '10.0.0.7 - - "POST /login HTTP/1.1" 401 12',
    fields: { srcIp: '10.0.0.7', method: 'POST', status: 401 },
  },
};

const scanner = {
  ...bruteForce,
  id: 11,
  title: 'scanner-user-agent',
  detail: 'matched scanner-user-agent',
  severity: 'WARNING',
  status: 'RESOLVED',
  groupKey: undefined,
  eventCount: 1,
};

const list = (items: unknown[], total = items.length) =>
  json(200, { items, page: 0, size: 25, total });

function listQuery(fetchMock: ReturnType<typeof stubBackend>, n: number): URLSearchParams {
  return new URL(callsTo(fetchMock, 'GET /api/alerts')[n].url).searchParams;
}

describe('alerts page', () => {
  it('lists alerts newest first with their severity and status', async () => {
    startTestSession();
    stubBackend({ 'GET /api/auth/me': me, 'GET /api/alerts': () => list([bruteForce, scanner]) });

    renderRoute('/alerts');

    const table = await screen.findByRole('table');
    const rows = within(table).getAllByRole('row').slice(1);
    expect(rows).toHaveLength(2);
    expect(within(rows[0]).getByRole('link', { name: 'brute-force-login' })).toHaveAttribute(
      'href',
      '/alerts/12',
    );
    expect(within(rows[0]).getByText('CRITICAL')).toBeInTheDocument();
    expect(within(rows[0]).getByText('New')).toBeInTheDocument();
    expect(within(rows[1]).getByText('Resolved')).toBeInTheDocument();
    expect(screen.getByText('2 alerts · page 1 of 1')).toBeInTheDocument();
  });

  it('filters on severity and status, through the URL', async () => {
    startTestSession();
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /api/alerts': (request) =>
        new URL(request.url).searchParams.has('severity')
          ? list([bruteForce])
          : list([bruteForce, scanner]),
    });
    const user = userEvent.setup();

    const { router } = renderRoute('/alerts');
    await screen.findByRole('table');
    const severity = screen.getByRole('group', { name: 'Severity' });
    await user.click(within(severity).getByRole('button', { name: 'CRITICAL' }));

    await waitFor(() => expect(screen.getByText('1 alert · page 1 of 1')).toBeInTheDocument());
    expect(within(severity).getByRole('button', { name: 'CRITICAL' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    expect(router.state.location.search).toBe('?severity=CRITICAL');
    expect(listQuery(fetchMock, 1).getAll('severity')).toEqual(['CRITICAL']);

    const status = screen.getByRole('group', { name: 'Status' });
    await user.click(within(status).getByRole('button', { name: 'New' }));
    await waitFor(() => expect(callsTo(fetchMock, 'GET /api/alerts')).toHaveLength(3));
    expect(listQuery(fetchMock, 2).getAll('status')).toEqual(['NEW']);
    expect(router.state.location.search).toBe('?severity=CRITICAL&status=NEW');

    await user.click(screen.getByRole('button', { name: 'Clear filters' }));
    expect(router.state.location.search).toBe('');
  });

  it('says when nothing matches', async () => {
    startTestSession();
    stubBackend({ 'GET /api/auth/me': me, 'GET /api/alerts': () => list([]) });

    renderRoute('/alerts?severity=DEBUG');

    expect(await screen.findByText('No alerts match these filters.')).toBeInTheDocument();
  });

  it('pages through a long list', async () => {
    startTestSession();
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /api/alerts': () => list([bruteForce], 60),
    });
    const user = userEvent.setup();

    const { router } = renderRoute('/alerts');
    await user.click(await screen.findByRole('button', { name: 'Next' }));

    expect(router.state.location.search).toBe('?page=2');
    await waitFor(() => expect(listQuery(fetchMock, 1).get('page')).toBe('1'));
  });

  it('opens an alert from the list and leads back to the same filters', async () => {
    startTestSession();
    stubBackend({
      'GET /api/auth/me': me,
      'GET /api/alerts': () => list([bruteForce]),
      'GET /api/alerts/12': () => json(200, bruteForce),
    });
    const user = userEvent.setup();

    const { router } = renderRoute('/alerts?severity=CRITICAL');
    await user.click(await screen.findByText('count = 6 (>= 5) within 1m for srcIp=10.0.0.7'));

    expect(await screen.findByRole('heading', { name: 'brute-force-login' })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/alerts/12');

    await user.click(screen.getByRole('link', { name: 'All alerts' }));
    expect(router.state.location.pathname).toBe('/alerts');
    expect(router.state.location.search).toBe('?severity=CRITICAL');
  });
});

describe('alert details', () => {
  it('shows the detection and the triggering event', async () => {
    startTestSession();
    stubBackend({ 'GET /api/auth/me': me, 'GET /api/alerts/12': () => json(200, bruteForce) });

    renderRoute('/alerts/12');

    expect(await screen.findByRole('heading', { name: 'brute-force-login' })).toBeInTheDocument();
    expect(screen.getByText('srcIp=10.0.0.7')).toBeInTheDocument();
    expect(screen.getByText('POST /login 401')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.7 - - "POST /login HTTP/1.1" 401 12')).toBeInTheDocument();
    expect(screen.getByText('web-1 (#3)')).toBeInTheDocument();
  });

  it('drills down to the events of the window and group', async () => {
    startTestSession();
    const fetchMock = stubBackend({
      'GET /api/auth/me': me,
      'GET /api/alerts/12': () => json(200, bruteForce),
      'GET /api/events/search': () => json(200, { hits: [], totalHits: 0 }),
    });
    const user = userEvent.setup();

    const { router } = renderRoute('/alerts/12');
    await user.click(await screen.findByRole('link', { name: 'View the 6 events' }));

    expect(await screen.findByRole('heading', { name: 'Events' })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/events');
    await waitFor(() => expect(callsTo(fetchMock, 'GET /api/events/search')).toHaveLength(1));
    const query = new URL(callsTo(fetchMock, 'GET /api/events/search')[0].url).searchParams;
    expect(query.get('from')).toBe('2026-10-01T10:00:00.000Z');
    expect(query.get('to')).toBe('2026-10-01T10:00:05.001Z');
    expect(query.getAll('srcIp')).toEqual(['10.0.0.7']);
    expect(query.get('order')).toBe('asc');
  });

  it('drills down from a field of the triggering event', async () => {
    startTestSession();
    stubBackend({ 'GET /api/auth/me': me, 'GET /api/alerts/12': () => json(200, bruteForce) });

    renderRoute('/alerts/12');

    const link = await screen.findByRole('link', { name: 'Events in the window with Status 401' });
    const params = new URLSearchParams(link.getAttribute('href')!.split('?')[1]);
    expect(params.getAll('status')).toEqual(['401']);
    expect(params.getAll('srcIp')).toEqual([]);
    expect(params.get('from')).toBe('2026-10-01T10:00:00.000Z');
  });

  it('says when the alert does not exist', async () => {
    startTestSession();
    stubBackend({
      'GET /api/auth/me': me,
      'GET /api/alerts/99': () => json(404, { error: 'not found' }),
    });

    renderRoute('/alerts/99');

    expect(await screen.findByRole('alert')).toHaveTextContent('Could not find alert #99.');
  });

  it('shows the model summary beside the rule severity', async () => {
    startTestSession();
    stubBackend({
      'GET /api/auth/me': me,
      'GET /api/alerts/12': () => json(200, { ...bruteForce, aiSummary }),
    });

    renderRoute('/alerts/12');

    const card = (await screen.findByRole('heading', { name: 'AI summary' })).closest(
      '[data-slot="card"]',
    ) as HTMLElement;
    expect(within(card).getByText(aiSummary.summary)).toBeInTheDocument();
    expect(within(card).getByText(aiSummary.recommendedAction)).toBeInTheDocument();
    expect(within(card).getByText('Brute force')).toBeInTheDocument();
    expect(within(card).getByText('ERROR')).toBeInTheDocument();
    expect(within(card).getByText(/anthropic\/claude-opus-5-5/)).toBeInTheDocument();
    // A viewer reads the summary but is not offered a new one.
    expect(within(card).queryByRole('button')).not.toBeInTheDocument();
  });

  it('lets an analyst have the alert summarised', async () => {
    startTestSession();
    const fetchMock = stubBackend({
      'GET /api/auth/me': analyst,
      'GET /api/alerts/12': () => json(200, bruteForce),
      'POST /api/alerts/12/summary': () => json(200, { ...bruteForce, aiSummary }),
    });
    const user = userEvent.setup();

    renderRoute('/alerts/12');
    expect(await screen.findByText('No model has summarised this alert yet.')).toBeInTheDocument();
    await user.click(await screen.findByRole('button', { name: 'Summarise' }));

    expect(await screen.findByText(aiSummary.summary)).toBeInTheDocument();
    expect(callsTo(fetchMock, 'POST /api/alerts/12/summary')).toHaveLength(1);
    expect(screen.getByRole('button', { name: 'Summarise again' })).toBeInTheDocument();
  });

  it('says when the AI provider failed', async () => {
    startTestSession();
    stubBackend({
      'GET /api/auth/me': analyst,
      'GET /api/alerts/12': () => json(200, bruteForce),
      'POST /api/alerts/12/summary': () =>
        json(502, {
          error: 'ai_summary_failed',
          message: 'The AI provider could not summarise this alert. The alert is unchanged.',
        }),
    });
    const user = userEvent.setup();

    renderRoute('/alerts/12');
    await user.click(await screen.findByRole('button', { name: 'Summarise' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The AI provider could not summarise this alert. The alert is unchanged.',
    );
  });
});
