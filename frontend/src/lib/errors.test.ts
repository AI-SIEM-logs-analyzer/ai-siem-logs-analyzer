import { ApiError } from '@/lib/api-client';
import { backendMessage, describeError, errorMessage, isChunkLoadError } from './errors';

const refusal = (status: number, body?: unknown, headers?: Record<string, string>) =>
  new ApiError(status, body, `/api/x failed with ${status}`, new Headers(headers));

describe('describeError', () => {
  it('never shows the raw status line', () => {
    for (const status of [400, 401, 403, 404, 408, 418, 429, 500, 502, 503, 504]) {
      expect(errorMessage(refusal(status))).not.toContain('failed with');
    }
  });

  it('offers a retry only where trying again can help', () => {
    expect(describeError(refusal(500)).retryable).toBe(true);
    expect(describeError(refusal(503)).retryable).toBe(true);
    expect(describeError(new TypeError('Failed to fetch')).retryable).toBe(true);
    expect(describeError(refusal(400)).retryable).toBe(false);
    expect(describeError(refusal(403)).retryable).toBe(false);
  });

  it('explains a connection that never answered', () => {
    expect(describeError(new TypeError('Failed to fetch'))).toMatchObject({
      title: 'Connection problem',
      message: 'Could not reach the server. Check your connection and try again.',
    });
    // A bug is not a connection problem, even though it is a TypeError too.
    expect(describeError(new TypeError('x is not a function')).title).toBe('Something went wrong');
  });

  it('passes on what the backend said about a refusal', () => {
    expect(errorMessage(refusal(400, { message: 'from must precede to' }))).toBe(
      'The server refused the request: from must precede to',
    );
  });

  it('says how long to wait when the server asks', () => {
    expect(errorMessage(refusal(429, {}, { 'Retry-After': '30' }))).toContain('Try again in 30 s.');
    expect(errorMessage(refusal(503, {}, { 'Retry-After': '600' }))).toContain(
      'Try again in 10 min.',
    );
  });

  it('names what failed to load', () => {
    expect(errorMessage(refusal(500), 'the users')).toContain('loading the users');
    expect(errorMessage(new Error('boom'), 'the users')).toContain(
      'stopped the users from loading',
    );
  });

  it('recognises a chunk that vanished with a new deployment', () => {
    const stale = new TypeError(
      'Failed to fetch dynamically imported module: /assets/events-page-abc.js',
    );
    expect(isChunkLoadError(stale)).toBe(true);
    expect(describeError(stale).title).toBe('New version available');
  });
});

describe('backendMessage', () => {
  it('reads a JSON message or a text body, and nothing else', () => {
    expect(backendMessage({ message: ' bad range ' })).toBe('bad range');
    expect(backendMessage('plain text')).toBe('plain text');
    expect(backendMessage({ error: 'code_only' })).toBeNull();
    expect(backendMessage('   ')).toBeNull();
    expect(backendMessage(undefined)).toBeNull();
  });
});
