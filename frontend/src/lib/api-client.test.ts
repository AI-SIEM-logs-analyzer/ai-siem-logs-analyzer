import { ApiError, apiFetch } from './api-client';

describe('apiFetch', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('parses JSON and asks for it', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response('{"ok":true}', { status: 200 })));
    vi.stubGlobal('fetch', fetchMock);

    await expect(apiFetch('/api/thing')).resolves.toEqual({ ok: true });
    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(new Headers(init.headers).get('Accept')).toBe('application/json');
  });

  it('throws ApiError with status and body outside 2xx', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(new Response('{"error":"nope"}', { status: 404 }))),
    );

    const error: unknown = await apiFetch('/api/missing').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 404, body: { error: 'nope' } });
  });

  it('returns the body for an accepted non-2xx status', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(new Response('{"status":"DOWN"}', { status: 503 }))),
    );

    await expect(apiFetch('/q/health', { acceptStatuses: [503] })).resolves.toEqual({
      status: 'DOWN',
    });
  });
});
