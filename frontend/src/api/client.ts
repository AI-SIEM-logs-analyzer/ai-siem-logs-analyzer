import { createApiClient } from '@/lib/api-client';
import { authFetch } from '@/lib/auth/auth-fetch';

/**
 * The authenticated, typed backend client. Calls carry the session's access token, and an
 * expiring or rejected token is renewed transparently — see `lib/auth/auth-fetch.ts`.
 *
 *     const user = await unwrap(api.GET('/api/auth/me'));
 */
export const api = createApiClient(authFetch);
