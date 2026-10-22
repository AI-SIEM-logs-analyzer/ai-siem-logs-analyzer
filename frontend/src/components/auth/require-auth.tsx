import type { ReactNode } from 'react';
import { Navigate, useLocation } from 'react-router';
import { getSessionEnd } from '@/lib/auth/session';
import { useSession } from '@/lib/auth/use-session';

export function RequireAuth({ children }: { children: ReactNode }) {
  const session = useSession();
  const location = useLocation();
  if (session) return children;

  const params = new URLSearchParams();
  const here = `${location.pathname}${location.search}${location.hash}`;
  if (here !== '/') params.set('redirect', here);
  if (getSessionEnd() === 'expired') params.set('expired', '1');
  const query = params.toString();
  return <Navigate to={query ? `/login?${query}` : '/login'} replace />;
}
