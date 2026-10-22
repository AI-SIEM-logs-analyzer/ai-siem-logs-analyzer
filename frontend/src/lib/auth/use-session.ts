import { useSyncExternalStore } from 'react';
import { getSession, subscribeSession, type Session } from './session';

export function useSession(): Session | null {
  return useSyncExternalStore(subscribeSession, getSession);
}
