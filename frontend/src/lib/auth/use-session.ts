import { useSyncExternalStore } from 'react';
import { getSession, subscribeSession, type Session } from './session';

/** The current session, re-rendering when it starts, is renewed or ends — in any tab. */
export function useSession(): Session | null {
  return useSyncExternalStore(subscribeSession, getSession);
}
