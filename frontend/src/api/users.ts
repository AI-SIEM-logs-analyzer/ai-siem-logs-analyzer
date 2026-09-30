import { useQuery } from '@tanstack/react-query';
import { api } from '@/api/client';
import type { components } from '@/api/schema';
import { unwrap } from '@/lib/api-client';

// /api/users: the accounts. Reading is open to every role; changing them is ADMIN only.

export type User = components['schemas']['UserResponse'];

export const userKeys = {
  all: ['users'] as const,
};

export function fetchUsers(): Promise<User[]> {
  return unwrap(api.GET('/api/users'));
}

export function useUsers() {
  return useQuery({ queryKey: userKeys.all, queryFn: fetchUsers });
}
