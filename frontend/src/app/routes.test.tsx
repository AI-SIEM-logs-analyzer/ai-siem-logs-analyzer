import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { getSession } from '@/lib/auth/session';
import { callsTo, json, startTestSession, stubBackend, tokens } from '@/test/backend-stub';
import { renderRoute } from '@/test/render-route';

const healthy = () => json(200, { status: 'UP', checks: [] });
const me = () => json(200, { id: 1, username: 'admin', roles: ['ADMIN'] });

describe('routes', () => {
  it('shows backend health on the dashboard', async () => {
    startTestSession();
    const fetchMock = stubBackend({
      'GET /q/health': () =>
        json(200, {
          status: 'UP',
          checks: [{ name: 'Database connections health check', status: 'UP' }],
        }),
      'GET /api/auth/me': me,
    });

    renderRoute('/');

    expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument();
    expect(await screen.findByText('Database connections health check')).toBeInTheDocument();
    expect(callsTo(fetchMock, 'GET /q/health')).toHaveLength(1);
  });

  it('renders a DOWN backend as data, not as an error', async () => {
    startTestSession();
    stubBackend({
      'GET /q/health': () =>
        json(503, { status: 'DOWN', checks: [{ name: 'OpenSearch', status: 'DOWN' }] }),
      'GET /api/auth/me': me,
    });

    renderRoute('/');

    expect(await screen.findByText('OpenSearch')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('navigates between pages from the sidebar', async () => {
    startTestSession();
    stubBackend({ 'GET /q/health': healthy, 'GET /api/auth/me': me });
    const user = userEvent.setup();

    renderRoute('/');
    const nav = screen.getByRole('navigation', { name: 'Main' });
    await user.click(within(nav).getByRole('link', { name: 'Events' }));

    expect(screen.getByRole('heading', { name: 'Events' })).toBeInTheDocument();
    expect(within(nav).getByRole('link', { name: 'Events' })).toHaveAttribute(
      'aria-current',
      'page',
    );
  });

  it('shows a not-found page for unknown paths', () => {
    startTestSession();
    stubBackend({ 'GET /api/auth/me': me });

    renderRoute('/no-such-page');

    expect(screen.getByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
  });
});

describe('authentication', () => {
  it('sends a signed-out visitor to sign in, then back where they were going', async () => {
    const fetchMock = stubBackend({
      'POST /api/auth/login': () => json(200, tokens('1')),
      'GET /api/auth/me': me,
    });
    const user = userEvent.setup();

    const { router } = renderRoute('/events?q=ssh');
    expect(router.state.location.pathname).toBe('/login');
    expect(router.state.location.search).toBe(`?redirect=${encodeURIComponent('/events?q=ssh')}`);

    await user.type(screen.getByLabelText('Username'), 'admin');
    await user.type(screen.getByLabelText('Password'), 'hunter2');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(await screen.findByRole('heading', { name: 'Events' })).toBeInTheDocument();
    expect(router.state.location.search).toBe('?q=ssh');
    const [login] = callsTo(fetchMock, 'POST /api/auth/login');
    expect(await login?.json()).toEqual({ username: 'admin', password: 'hunter2' });
    expect(await screen.findByText('admin')).toBeInTheDocument();
  });

  it('says so when the credentials are wrong', async () => {
    stubBackend({ 'POST /api/auth/login': () => json(401, { error: 'invalid_credentials' }) });
    const user = userEvent.setup();

    renderRoute('/login');
    await user.type(screen.getByLabelText('Username'), 'admin');
    await user.type(screen.getByLabelText('Password'), 'wrong');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid username or password.');
    expect(getSession()).toBeNull();
  });

  it('tells a throttled user how long to wait', async () => {
    stubBackend({
      'POST /api/auth/login': () =>
        json(429, { error: 'too_many_attempts' }, { 'Retry-After': '600' }),
    });
    const user = userEvent.setup();

    renderRoute('/login');
    await user.type(screen.getByLabelText('Username'), 'admin');
    await user.type(screen.getByLabelText('Password'), 'x');
    await user.click(screen.getByRole('button', { name: 'Sign in' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('Try again in 10 min.');
  });

  it('does not follow a redirect off this origin', async () => {
    startTestSession();
    stubBackend({ 'GET /q/health': healthy, 'GET /api/auth/me': me });

    const { router } = renderRoute('/login?redirect=//evil.example/phish');

    expect(await screen.findByRole('heading', { name: 'Dashboard' })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/');
  });

  it('returns to sign-in, saying why, once the session cannot be renewed', async () => {
    startTestSession();
    stubBackend({
      'GET /q/health': healthy,
      'GET /api/auth/me': () => json(401, { error: 'token_revoked' }),
      'POST /api/auth/refresh': () => json(401, { error: 'invalid_credentials' }),
    });

    const { router } = renderRoute('/alerts');

    expect(
      await screen.findByText('Your session has expired. Sign in again to continue.'),
    ).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/login');
    expect(new URLSearchParams(router.state.location.search).get('redirect')).toBe('/alerts');
  });

  it('signs out on the backend and locally', async () => {
    startTestSession();
    const fetchMock = stubBackend({
      'GET /q/health': healthy,
      'GET /api/auth/me': me,
      'POST /api/auth/logout': () => new Response(null, { status: 204 }),
    });
    const user = userEvent.setup();

    const { router } = renderRoute('/');
    await user.click(await screen.findByRole('button', { name: 'Sign out' }));

    expect(await screen.findByRole('button', { name: 'Sign in' })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe('/login');
    const [logout] = callsTo(fetchMock, 'POST /api/auth/logout');
    expect(logout?.headers.get('Authorization')).toBe('Bearer access-1');
    expect(await logout?.json()).toEqual({ refreshToken: 'refresh-1' });
    expect(getSession()).toBeNull();
    expect(localStorage.length).toBe(0);
  });
});
