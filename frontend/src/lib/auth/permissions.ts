import type { components } from '@/api/schema';

// What the signed-in account may do, derived from its roles. The backend enforces every one of
// these with @RolesAllowed; the UI only mirrors them, so that nobody is offered an action or a
// page that would answer 403. Hiding is a courtesy, never the control.

export type Role = components['schemas']['Role'];

export type Permission = 'logs:upload' | 'users:manage';

/** The roles each action needs, one entry per backend check the UI has something to show for. */
const ALLOWED: Record<Permission, readonly Role[]> = {
  // LogUploadResource / LogRootUploadResource: POST upload.
  'logs:upload': ['ADMIN', 'ANALYST'],
  // UserResource: create, update, change password, delete.
  'users:manage': ['ADMIN'],
};

/** Whether an account holding `roles` may do `permission`. No roles, no permission. */
export function can(roles: readonly Role[] | undefined, permission: Permission): boolean {
  return roles?.some((role) => ALLOWED[permission].includes(role)) ?? false;
}

const ROLE_ORDER: readonly Role[] = ['ADMIN', 'ANALYST', 'VIEWER'];

/** The most capable of `roles`, for showing one label per account. */
export function primaryRole(roles: readonly Role[] | undefined): Role | undefined {
  return ROLE_ORDER.find((role) => roles?.includes(role));
}

export const roleLabels: Record<Role, string> = {
  ADMIN: 'Admin',
  ANALYST: 'Analyst',
  VIEWER: 'Viewer',
};
