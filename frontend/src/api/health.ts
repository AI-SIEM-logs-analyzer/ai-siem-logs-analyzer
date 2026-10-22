import { useQuery } from '@tanstack/react-query';
import { api } from '@/api/client';
import type { components } from '@/api/schema';
import { unwrap } from '@/lib/api-client';

export type HealthReport = components['schemas']['HealthResponse'];
export type HealthStatus = NonNullable<HealthReport['status']>;

export const healthKeys = {
  all: ['health'] as const,
};

export function fetchHealth(): Promise<HealthReport> {
  return unwrap(api.GET('/q/health'), { acceptStatuses: [503] });
}

export function useBackendHealth() {
  return useQuery({
    queryKey: healthKeys.all,
    queryFn: fetchHealth,
    refetchInterval: 30_000,
  });
}
