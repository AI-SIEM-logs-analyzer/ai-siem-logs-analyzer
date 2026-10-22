import type { ReactNode } from 'react';
import { useCan } from '@/api/auth';
import type { Permission } from '@/lib/auth/permissions';

export function Can({ permission, children }: { permission: Permission; children: ReactNode }) {
  return useCan(permission) ? children : null;
}
