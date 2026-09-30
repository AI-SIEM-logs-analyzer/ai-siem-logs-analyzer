import { startSession, type Session } from '@/lib/auth/session';

type Handler = (request: Request) => Response | Promise<Response>;

/** A JSON response, as the backend would send it. */
export function json(status: number, body: unknown, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

/**
 * Replaces `fetch` with a fake backend keyed by `"METHOD /path"`. An unlisted route answers
 * 404, so a test sees a call it did not expect as a failure rather than a hang.
 */
export function stubBackend(routes: Record<string, Handler>) {
  const fetchMock = vi.fn((request: Request) => {
    const handler = routes[`${request.method} ${new URL(request.url).pathname}`];
    return Promise.resolve(handler ? handler(request) : json(404, { error: 'not stubbed' }));
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

/** The requests the stub received for one route, in order. */
export function callsTo(fetchMock: ReturnType<typeof stubBackend>, route: string): Request[] {
  return fetchMock.mock.calls
    .map(([request]) => request)
    .filter((request) => `${request.method} ${new URL(request.url).pathname}` === route);
}

/** Signs in without a backend: stores the pair `tokens(suffix, expiresIn)` as the session. */
export function startTestSession(expiresIn = 900, suffix = '1'): Session {
  return startSession(tokens(suffix, expiresIn));
}

/** A token pair as /api/auth/login and /api/auth/refresh return it. */
export function tokens(suffix: string, expiresIn = 900) {
  return {
    accessToken: `access-${suffix}`,
    refreshToken: `refresh-${suffix}`,
    tokenType: 'Bearer',
    expiresIn,
  };
}
