import { createApiClient, unwrap as baseUnwrap, type UnwrapOptions } from '@/lib/api-client';
import { authFetch } from '@/lib/auth/auth-fetch';

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
