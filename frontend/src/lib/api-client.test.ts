import { json, stubBackend } from '@/test/backend-stub';
import { ApiError, publicApi, unwrap } from './api-client';

describe('unwrap', () => {
  it('resolves to the parsed body of a 2xx', async () => {
    stubBackend({ 'POST /api/auth/login': () => json(200, { accessToken: 'a' }) });

    await expect(
      unwrap(publicApi.POST('/api/auth/login', { body: { username: 'u', password: 'p' } })),
    ).resolves.toEqual({ accessToken: 'a' });
  });

  it('throws ApiError with status, body and headers outside 2xx', async () => {
    stubBackend({
      'POST /api/auth/login': () =>
        json(429, { error: 'too_many_attempts' }, { 'Retry-After': '60' }),
    });

    const error: unknown = await unwrap(
      publicApi.POST('/api/auth/login', { body: { username: 'u', password: 'p' } }),
    ).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 429, body: { error: 'too_many_attempts' } });
    expect((error as ApiError).headers.get('Retry-After')).toBe('60');
  });

  it('returns the body for an accepted non-2xx status', async () => {
    stubBackend({ 'GET /q/health': () => json(503, { status: 'DOWN', checks: [] }) });

    await expect(unwrap(publicApi.GET('/q/health'), { acceptStatuses: [503] })).resolves.toEqual({
      status: 'DOWN',
      checks: [],
    });
  });
});
