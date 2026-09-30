import type { ReactNode } from 'react';
import { useCan } from '@/api/auth';
import type { Permission } from '@/lib/auth/permissions';

/** Renders `children` only for an account allowed `permission`; nothing while its roles load. */
export function Can({ permission, children }: { permission: Permission; children: ReactNode }) {
  return useCan(permission) ? children : null;
}
