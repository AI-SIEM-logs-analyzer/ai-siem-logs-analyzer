import { publicApi } from '@/lib/api-client';
import { endSession, getSession, reloadSession, startSession, type Session } from './session';

const REFRESH_MARGIN_MS = 30_000;

const REFRESH_LOCK = 'siem.auth.refresh';

const PUBLIC_PATHS = ['/api/auth/login', '/api/auth/refresh'];

export async function authFetch(request: Request): Promise<Response> {
  if (PUBLIC_PATHS.some((path) => new URL(request.url).pathname.endsWith(path))) {
    return globalThis.fetch(request);
  }

  const replay = request.clone();
  const session = await freshSession();
  const response = await globalThis.fetch(withBearer(request, session));
  if (response.status !== 401 || !session) return response;

  const renewed = await refreshSession(session);
  if (!renewed || renewed.accessToken === session.accessToken) return response;
  return globalThis.fetch(withBearer(replay, renewed));
}

export async function freshSession(now = Date.now()): Promise<Session | null> {
  const session = getSession();
  if (session && session.expiresAt - now < REFRESH_MARGIN_MS) return refreshSession(session);
  return session;
}

let pending: Promise<Session | null> | null = null;

export function refreshSession(stale: Session): Promise<Session | null> {
  pending ??= withLock(() => rotate(stale)).finally(() => {
    pending = null;
  });
  return pending;
}

async function rotate(stale: Session): Promise<Session | null> {
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

  if (result.response.status === 401 || result.response.status === 400) {
    endSession('expired');
    return null;
  }
  return latest;
}

async function withLock<T>(task: () => Promise<T>): Promise<T> {
  if (!('locks' in navigator)) return task();
  return await navigator.locks.request(REFRESH_LOCK, task);
}

function withBearer(request: Request, session: Session | null): Request {
  if (!session) return request;
  const headers = new Headers(request.headers);
  headers.set('Authorization', `Bearer ${session.accessToken}`);
  return new Request(request, { headers });
}
