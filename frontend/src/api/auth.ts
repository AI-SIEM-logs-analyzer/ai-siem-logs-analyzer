import { useQuery } from '@tanstack/react-query';
import { api } from '@/api/client';
import type { components } from '@/api/schema';
import { publicApi, unwrap } from '@/lib/api-client';
import { freshSession } from '@/lib/auth/auth-fetch';
import { can, type Permission } from '@/lib/auth/permissions';
import { endSession, startSession } from '@/lib/auth/session';

export type LoginRequest = components['schemas']['LoginRequest'];
export type CurrentUser = components['schemas']['UserResponse'];

export const authKeys = {
  me: ['auth', 'me'] as const,
};

export async function signIn(credentials: LoginRequest): Promise<void> {
  startSession(await unwrap(publicApi.POST('/api/auth/login', { body: credentials })));
}

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

/**
 * Whether the signed-in account may do `permission`. False until its roles are known, so an
 * action never flashes up for someone who turns out not to be allowed it.
 */
export function useCan(permission: Permission): boolean {
  const { data: user } = useCurrentUser();
  return can(user?.roles, permission);
}
