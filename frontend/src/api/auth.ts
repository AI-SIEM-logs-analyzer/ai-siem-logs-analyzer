import { useQuery } from '@tanstack/react-query';
import { api } from '@/api/client';
import type { components } from '@/api/schema';
import { publicApi, unwrap } from '@/lib/api-client';
import { freshSession } from '@/lib/auth/auth-fetch';
import { endSession, startSession } from '@/lib/auth/session';

// /api/auth: sign-in, sign-out and the signed-in account.

export type LoginRequest = components['schemas']['LoginRequest'];
export type CurrentUser = components['schemas']['UserResponse'];

export const authKeys = {
  me: ['auth', 'me'] as const,
};

/** Exchanges credentials for a session. Rejects with `ApiError` (401 wrong credentials, 429 throttled). */
export async function signIn(credentials: LoginRequest): Promise<void> {
  startSession(await unwrap(publicApi.POST('/api/auth/login', { body: credentials })));
}

/**
 * Ends the session here and, as far as it can, on the backend.
 *
 * The call goes through `publicApi` with the bearer set by hand: the authenticated client would
 * refresh on a 401 and replay a body naming the refresh token that refresh just retired, leaving
 * the new one live. Renewing first, then naming the current token, revokes the right one. The
 * local session ends whatever the backend answers — signing out must never fail.
 */
export async function signOut(): Promise<void> {
  const session = await freshSession();
  if (!session) return;
  try {
    await publicApi.POST('/api/auth/logout', {
      body: { refreshToken: session.refreshToken },
      headers: { Authorization: `Bearer ${session.accessToken}` },
    });
  } catch {
    // Unreachable backend: the tokens expire on their own.
  } finally {
    endSession('signed-out');
  }
}

export function fetchCurrentUser(): Promise<CurrentUser> {
  return unwrap(api.GET('/api/auth/me'));
}

export function useCurrentUser() {
  return useQuery({
    queryKey: authKeys.me,
    queryFn: fetchCurrentUser,
    staleTime: 5 * 60_000,
  });
}
