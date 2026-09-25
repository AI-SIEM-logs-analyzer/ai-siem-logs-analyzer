import { publicApi } from '@/lib/api-client';
import { endSession, getSession, reloadSession, startSession, type Session } from './session';

// The fetch behind the authenticated client. It attaches the access token, renews the session
// shortly before the token runs out, and once more when the backend still answers 401 (a token
// signed out elsewhere, a clock that disagrees with the server's). A session that cannot be
// renewed is ended; RequireAuth sees that and sends the user to the sign-in page.

/** Renew this long before the access token expires, so a request never races its expiry. */
const REFRESH_MARGIN_MS = 30_000;

/** Web Lock that serialises refreshes across every tab of this origin. */
const REFRESH_LOCK = 'siem.auth.refresh';

/** Endpoints that serve a caller with no session: a bearer there is noise and a 401 is final. */
const PUBLIC_PATHS = ['/api/auth/login', '/api/auth/refresh'];

export async function authFetch(request: Request): Promise<Response> {
  if (PUBLIC_PATHS.some((path) => new URL(request.url).pathname.endsWith(path))) {
    return globalThis.fetch(request);
  }

  // A request body can be read once; the copy is what a retry sends.
  const replay = request.clone();
  const session = await freshSession();
  const response = await globalThis.fetch(withBearer(request, session));
  if (response.status !== 401 || !session) return response;

  const renewed = await refreshSession(session);
  if (!renewed || renewed.accessToken === session.accessToken) return response;
  return globalThis.fetch(withBearer(replay, renewed));
}

/** The current session, renewed first if its access token is about to expire. */
export async function freshSession(now = Date.now()): Promise<Session | null> {
  const session = getSession();
  if (session && session.expiresAt - now < REFRESH_MARGIN_MS) return refreshSession(session);
  return session;
}

let pending: Promise<Session | null> | null = null;

/**
 * Exchanges the refresh token of `stale` for a new pair, at most once at a time.
 *
 * Every caller that finds the same token wanting shares one exchange: in this tab through
 * `pending`, across tabs through a Web Lock. Resolves to the renewed session, to `null` once the
 * backend has refused the token (the session is then ended), or to the unchanged session when
 * the backend could not be reached, which is no reason to sign anyone out.
 */
export function refreshSession(stale: Session): Promise<Session | null> {
  pending ??= withLock(() => rotate(stale)).finally(() => {
    pending = null;
  });
  return pending;
}

async function rotate(stale: Session): Promise<Session | null> {
  // Inside the lock, storage is the truth: a tab that held the lock before this one may
  // already have spent `stale`'s refresh token, and spending it again would be a replay.
  const latest = reloadSession();
  if (!latest || latest.refreshToken !== stale.refreshToken) return latest;

  let result;
  try {
    result = await publicApi.POST('/api/auth/refresh', {
      body: { refreshToken: latest.refreshToken },
    });
  } catch {
    return latest;
  }

  if (result.data) return startSession(result.data);
  // 401: expired, revoked or replayed. 400: no longer a token the backend recognises at all.
  if (result.response.status === 401 || result.response.status === 400) {
    endSession('expired');
    return null;
  }
  return latest;
}

async function withLock<T>(task: () => Promise<T>): Promise<T> {
  // Web Locks are in every current browser; jsdom lacks them, and one tab needs no lock.
  if (!('locks' in navigator)) return task();
  return await navigator.locks.request(REFRESH_LOCK, task);
}

function withBearer(request: Request, session: Session | null): Request {
  if (!session) return request;
  const headers = new Headers(request.headers);
  headers.set('Authorization', `Bearer ${session.accessToken}`);
  return new Request(request, { headers });
}
