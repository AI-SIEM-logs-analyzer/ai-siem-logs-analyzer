import type { components } from '@/api/schema';

type TokenResponse = components['schemas']['TokenResponse'];

export interface Session {
  accessToken: string;
  refreshToken: string;

  expiresAt: number;
}

export type SessionEnd = 'signed-out' | 'expired';

const STORAGE_KEY = 'siem.auth.session';

let current: Session | null = load();
let lastEnd: SessionEnd | null = null;
const listeners = new Set<() => void>();

export function getSession(): Session | null {
  return current;
}

export function getSessionEnd(): SessionEnd | null {
  return lastEnd;
}

export function startSession(tokens: TokenResponse, now = Date.now()): Session {
  const { accessToken, refreshToken, expiresIn } = tokens;
  if (!accessToken || !refreshToken || expiresIn === undefined) {
    throw new Error('the token response is missing a token or its lifetime');
  }
  const session = { accessToken, refreshToken, expiresAt: now + expiresIn * 1000 };
  lastEnd = null;
  update(session);
  return session;
}

export function endSession(reason: SessionEnd): void {
  if (!current) return;
  lastEnd = reason;
  update(null);
}

export function reloadSession(): Session | null {
  const stored = load();
  if (!sameSession(stored, current)) {
    if (!stored) lastEnd = 'signed-out';
    current = stored;
    notify();
  }
  return current;
}

export function subscribeSession(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

window.addEventListener('storage', (event) => {
  if (event.key === STORAGE_KEY || event.key === null) reloadSession();
});

function update(session: Session | null) {
  current = session;
  try {
    if (session) localStorage.setItem(STORAGE_KEY, JSON.stringify(session));
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    void 0;
  }
  notify();
}

function notify() {
  listeners.forEach((listener) => listener());
}

function load(): Session | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const value = JSON.parse(raw) as Partial<Session>;
    return typeof value.accessToken === 'string' &&
      typeof value.refreshToken === 'string' &&
      typeof value.expiresAt === 'number'
      ? {
          accessToken: value.accessToken,
          refreshToken: value.refreshToken,
          expiresAt: value.expiresAt,
        }
      : null;
  } catch {
    return null;
  }
}

function sameSession(a: Session | null, b: Session | null): boolean {
  return a?.accessToken === b?.accessToken && a?.refreshToken === b?.refreshToken;
}
