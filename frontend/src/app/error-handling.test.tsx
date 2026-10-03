import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { createMemoryRouter, Outlet, RouterProvider } from 'react-router';
import { OfflineBanner } from '@/components/layout/offline-banner';
import { RouteErrorPage } from '@/pages/route-error-page';
import { callsTo, json, startTestSession, stubBackend } from '@/test/backend-stub';
import { renderRoute } from '@/test/render-route';

const analyst = () => json(200, { id: 2, username: 'anna', roles: ['ANALYST'] });

describe('error states', () => {
  it('explains a failed list in plain words and loads it again on request', async () => {
    startTestSession();
    let failures = 1;
    const fetchMock = stubBackend({
      'GET /api/auth/me': analyst,
      'GET /api/logs/uploads': () =>
        failures-- > 0
          ? json(500, { error: 'internal' })
          : json(200, { items: [], page: 0, size: 20, total: 0 }),
    });
    const user = userEvent.setup();

    renderRoute('/uploads');

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Server error');
    expect(alert).toHaveTextContent('The server ran into a problem loading the uploads.');
    expect(alert).not.toHaveTextContent('failed with 500');

    await user.click(screen.getByRole('button', { name: 'Try again' }));
    expect(await screen.findByText('No log files have been uploaded yet.')).toBeInTheDocument();
    expect(callsTo(fetchMock, 'GET /api/logs/uploads')).toHaveLength(2);
  });

  it('offers no retry for a refusal that would only repeat', async () => {
    startTestSession();
    stubBackend({
      'GET /api/auth/me': analyst,
      'GET /api/logs/uploads': () => json(403, {}),
    });

    renderRoute('/uploads');

    expect(await screen.findByRole('alert')).toHaveTextContent('Not allowed');
    expect(screen.queryByRole('button', { name: 'Try again' })).not.toBeInTheDocument();
  });

  it('shows a skeleton while a list loads', async () => {
    startTestSession();
    stubBackend({
      'GET /api/auth/me': analyst,
      'GET /api/logs/uploads': () => new Promise<Response>(() => {}),
    });

    renderRoute('/uploads');

    expect(await screen.findByRole('status', { name: 'Loading uploads' })).toBeInTheDocument();
  });
});

describe('route error boundary', () => {
  function Broken(): never {
    throw new Error('Cannot read properties of undefined');
  }

  function mount(element: React.ReactNode) {
    const router = createMemoryRouter(
      [
        {
          path: '/',
          element: (
            <div>
              <nav aria-label="Main">sidebar</nav>
              <Outlet />
            </div>
          ),
          errorElement: <RouteErrorPage />,
          children: [
            {
              errorElement: <RouteErrorPage variant="page" />,
              children: [{ index: true, element }],
            },
          ],
        },
      ],
      { initialEntries: ['/'] },
    );
    return render(<RouterProvider router={router} />);
  }

  beforeEach(() => {
    // React logs the caught render error; the boundary is what this test is about.
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('keeps the layout around a page that fails to render', () => {
    mount(<Broken />);

    expect(screen.getByRole('heading', { name: 'Something went wrong' })).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent('This page hit an unexpected error.');
    expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Reload the page' })).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Back to the dashboard' })).toHaveAttribute(
      'href',
      '/',
    );
    // The raw message is kept for whoever looks into it, folded away.
    expect(screen.getByText('Cannot read properties of undefined')).not.toBeVisible();
  });

  it('asks for a reload when a page chunk vanished with a deployment', () => {
    function Stale(): never {
      throw new TypeError('Failed to fetch dynamically imported module: /assets/events.js');
    }
    mount(<Stale />);

    expect(screen.getByRole('heading', { name: 'New version available' })).toBeInTheDocument();
  });
});

describe('offline banner', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('appears while the browser is offline and leaves once it is back', () => {
    const onLine = vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(true);
    render(<OfflineBanner />);
    expect(screen.queryByText(/You are offline/)).not.toBeInTheDocument();

    onLine.mockReturnValue(false);
    act(() => void window.dispatchEvent(new Event('offline')));
    expect(screen.getByRole('status')).toHaveTextContent('You are offline.');

    onLine.mockReturnValue(true);
    act(() => void window.dispatchEvent(new Event('online')));
    expect(screen.queryByText(/You are offline/)).not.toBeInTheDocument();
  });
});
