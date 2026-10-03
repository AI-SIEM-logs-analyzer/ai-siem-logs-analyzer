import { WifiOff } from 'lucide-react';
import { useSyncExternalStore } from 'react';

function subscribe(onChange: () => void) {
  window.addEventListener('online', onChange);
  window.addEventListener('offline', onChange);
  return () => {
    window.removeEventListener('online', onChange);
    window.removeEventListener('offline', onChange);
  };
}

/** Whether the browser believes it has a network connection. */
function useOnline(): boolean {
  return useSyncExternalStore(subscribe, () => navigator.onLine);
}

/**
 * Says so while the browser is offline, once for the whole app, so each failed card does not
 * have to. TanStack Query pauses its requests meanwhile and resumes them on reconnect.
 */
export function OfflineBanner() {
  if (useOnline()) return null;
  return (
    <div
      role="status"
      className="flex items-center justify-center gap-2 bg-amber-100 px-4 py-2 text-center text-sm text-amber-950 dark:bg-amber-950 dark:text-amber-100"
    >
      <WifiOff className="size-4 shrink-0" aria-hidden />
      You are offline. Data shown may be out of date; it refreshes once the connection is back.
    </div>
  );
}
