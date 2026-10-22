import type { components } from '@/api/schema';

export type Role = components['schemas']['Role'];

export type Permission = 'alerts:summarize' | 'logs:upload' | 'users:manage';

const ALLOWED: Record<Permission, readonly Role[]> = {
  'alerts:summarize': ['ADMIN', 'ANALYST'],

  'logs:upload': ['ADMIN', 'ANALYST'],

  'users:manage': ['ADMIN'],
};

export function can(roles: readonly Role[] | undefined, permission: Permission): boolean {
  return roles?.some((role) => ALLOWED[permission].includes(role)) ?? false;
}

const ROLE_ORDER: readonly Role[] = ['ADMIN', 'ANALYST', 'VIEWER'];

export function primaryRole(roles: readonly Role[] | undefined): Role | undefined {
  return ROLE_ORDER.find((role) => roles?.includes(role));
}

export const roleLabels: Record<Role, string> = {
  ADMIN: 'Admin',
  ANALYST: 'Analyst',
  VIEWER: 'Viewer',
};
