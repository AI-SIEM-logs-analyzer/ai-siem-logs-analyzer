import { screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { renderRoute } from '@/test/render-route';

function stubFetch(status: number, body: unknown) {
  const fetchMock = vi.fn(() => Promise.resolve(new Response(JSON.stringify(body), { status })));
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

describe('routes', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('shows backend health on the dashboard', async () => {
    const fetchMock = stubFetch(200, {
      status: 'UP',
      checks: [{ name: 'Database connections health check', status: 'UP' }],
    });

    renderRoute('/');

    expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument();
    expect(await screen.findByText('Database connections health check')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/q/health', expect.anything());
  });

  it('renders a DOWN backend as data, not as an error', async () => {
    stubFetch(503, { status: 'DOWN', checks: [{ name: 'OpenSearch', status: 'DOWN' }] });

    renderRoute('/');

    expect(await screen.findByText('OpenSearch')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('navigates between pages from the sidebar', async () => {
    stubFetch(200, { status: 'UP', checks: [] });
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
    renderRoute('/no-such-page');

    expect(screen.getByRole('heading', { name: 'Page not found' })).toBeInTheDocument();
  });
});
