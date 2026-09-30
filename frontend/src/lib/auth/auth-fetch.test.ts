import { api } from '@/api/client';
import { ApiError, unwrap } from '@/lib/api-client';
import { callsTo, json, startTestSession, stubBackend, tokens } from '@/test/backend-stub';
import { getSession, getSessionEnd } from './session';

const me = { id: 1, username: 'admin' };

/** A /me that accepts only the given access token, as the backend would. */
function meFor(accessToken: string) {
  return (request: Request) =>
    request.headers.get('Authorization') === `Bearer ${accessToken}`
      ? json(200, me)
      : json(401, { error: 'invalid_token' });
}

describe('authFetch', () => {
  it('sends the access token as a bearer', async () => {
    startTestSession();
    const fetchMock = stubBackend({ 'GET /api/auth/me': meFor('access-1') });

    await expect(unwrap(api.GET('/api/auth/me'))).resolves.toEqual(me);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('renews a token about to expire before using it', async () => {
    startTestSession(10);
    const fetchMock = stubBackend({
      'POST /api/auth/refresh': () => json(200, tokens('2')),
      'GET /api/auth/me': meFor('access-2'),
    });

    await expect(unwrap(api.GET('/api/auth/me'))).resolves.toEqual(me);

    const [refresh] = callsTo(fetchMock, 'POST /api/auth/refresh');
    expect(await refresh?.json()).toEqual({ refreshToken: 'refresh-1' });
    expect(callsTo(fetchMock, 'GET /api/auth/me')).toHaveLength(1);
    expect(getSession()).toMatchObject({ accessToken: 'access-2', refreshToken: 'refresh-2' });
  });

  it('renews on a 401 and replays the request, body included', async () => {
    startTestSession();
    const fetchMock = stubBackend({
      'POST /api/auth/refresh': () => json(200, tokens('2')),
      'POST /api/users': (request) =>
        request.headers.get('Authorization') === 'Bearer access-2'
          ? json(200, { id: 7 })
          : json(401, { error: 'token_revoked' }),
    });

    const created = await unwrap(
      api.POST('/api/users', {
        body: { username: 'bob', password: 'long-enough-secret', roles: ['VIEWER'] },
      }),
    );

    expect(created).toEqual({ id: 7 });
    const attempts = callsTo(fetchMock, 'POST /api/users');
    expect(attempts).toHaveLength(2);
    expect(await attempts[1]?.json()).toMatchObject({ username: 'bob' });
  });

  it('shares one refresh between concurrent requests', async () => {
    startTestSession();
    const fetchMock = stubBackend({
      'POST /api/auth/refresh': () => json(200, tokens('2')),
      'GET /api/auth/me': meFor('access-2'),
    });

    await Promise.all([
      unwrap(api.GET('/api/auth/me')),
      unwrap(api.GET('/api/auth/me')),
      unwrap(api.GET('/api/auth/me')),
    ]);

    // A second exchange of refresh-1 would be a replay, which revokes every session.
    expect(callsTo(fetchMock, 'POST /api/auth/refresh')).toHaveLength(1);
  });

  it('uses a token another tab already rotated instead of spending the old one again', async () => {
    startTestSession();
    // Another tab refreshed: storage moved on, this tab has not heard yet.
    localStorage.setItem(
      'siem.auth.session',
      JSON.stringify({ ...tokens('2'), expiresAt: Date.now() + 900_000 }),
    );
    const fetchMock = stubBackend({ 'GET /api/auth/me': meFor('access-2') });

    await expect(unwrap(api.GET('/api/auth/me'))).resolves.toEqual(me);
    expect(callsTo(fetchMock, 'POST /api/auth/refresh')).toHaveLength(0);
  });

  it('ends the session as expired when the refresh token is refused', async () => {
    startTestSession();
    stubBackend({
      'POST /api/auth/refresh': () => json(401, { error: 'invalid_credentials' }),
      'GET /api/auth/me': meFor('never'),
    });

    const error: unknown = await unwrap(api.GET('/api/auth/me')).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 401 });
    expect(getSession()).toBeNull();
    expect(getSessionEnd()).toBe('expired');
  });

  it('keeps the session when the backend cannot be reached to refresh it', async () => {
    startTestSession();
    stubBackend({
      'POST /api/auth/refresh': () => Promise.reject(new TypeError('Failed to fetch')),
      'GET /api/auth/me': meFor('never'),
    });

    await expect(unwrap(api.GET('/api/auth/me'))).rejects.toMatchObject({ status: 401 });
    expect(getSession()).toMatchObject({ refreshToken: 'refresh-1' });
  });

  it('neither authenticates nor retries the sign-in call', async () => {
    startTestSession();
    const fetchMock = stubBackend({
      'POST /api/auth/login': () => json(401, { error: 'invalid_credentials' }),
    });

    await expect(
      unwrap(api.POST('/api/auth/login', { body: { username: 'u', password: 'p' } })),
    ).rejects.toMatchObject({ status: 401 });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0].headers.has('Authorization')).toBe(false);
  });
});
