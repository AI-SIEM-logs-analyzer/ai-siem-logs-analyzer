import { LogOut, Shield } from 'lucide-react';
import { useState } from 'react';
import { NavLink, Outlet } from 'react-router';
import { signOut, useCurrentUser } from '@/api/auth';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { navItems } from './nav-items';

export function AppLayout() {
  return (
    <div className="flex min-h-svh flex-col md:flex-row">
      <aside className="border-sidebar-border bg-sidebar text-sidebar-foreground flex shrink-0 flex-col border-b md:w-60 md:border-r md:border-b-0">
        <div className="flex h-14 items-center gap-2 px-4 font-semibold">
          <Shield className="size-5" aria-hidden />
          <span>SIEM Analyzer</span>
        </div>
        <nav aria-label="Main" className="flex gap-1 overflow-x-auto px-2 pb-2 md:flex-col">
          {navItems.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium whitespace-nowrap transition-colors',
                  'hover:bg-sidebar-accent hover:text-sidebar-accent-foreground',
                  isActive && 'bg-sidebar-accent text-sidebar-accent-foreground',
                )
              }
            >
              <Icon className="size-4" aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>
        <UserPanel />
      </aside>
      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto flex max-w-6xl flex-col gap-6 p-4 md:p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

function UserPanel() {
  const { data: user } = useCurrentUser();
  const [signingOut, setSigningOut] = useState(false);

  return (
    <div className="border-sidebar-border flex items-center justify-between gap-2 border-t px-4 py-3 md:mt-auto">
      <span className="truncate text-sm" title={user?.username}>
        {user?.username ?? '…'}
      </span>
      <Button
        variant="ghost"
        size="sm"
        disabled={signingOut}
        onClick={() => {
          setSigningOut(true);
          // Ending the session is what leaves the page: RequireAuth redirects to /login.
          void signOut().finally(() => setSigningOut(false));
        }}
      >
        <LogOut aria-hidden />
        Sign out
      </Button>
    </div>
  );
}
