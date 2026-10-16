import { createApiClient, unwrap as baseUnwrap, type UnwrapOptions } from '@/lib/api-client';
import { authFetch } from '@/lib/auth/auth-fetch';

/**
 * The authenticated, typed backend client. Calls carry the session's access token, and an
 * expiring or rejected token is renewed transparently — see `lib/auth/auth-fetch.ts`.
 *
 *     const user = await unwrap(api.GET('/api/auth/me'));
 */
export const api = createApiClient(authFetch);
export const apiClient = api;

export function unwrap<T>(
  resultOrPromise:
    | Promise<{ data?: T; error?: unknown; response: Response }>
    | { data?: T; error?: unknown; response: Response },
  options?: UnwrapOptions,
): Promise<T> {
  return baseUnwrap(Promise.resolve(resultOrPromise), options);
}
