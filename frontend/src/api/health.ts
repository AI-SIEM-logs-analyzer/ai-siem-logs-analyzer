import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '@/lib/api-client';

// SmallRye Health (`/q/health`). It answers 503 with the same body when any check is DOWN,
// so a DOWN backend is data to render, not a failed request.

export type HealthStatus = 'UP' | 'DOWN';

export interface HealthCheck {
  name: string;
  status: HealthStatus;
  data?: Record<string, unknown>;
}

export interface HealthReport {
  status: HealthStatus;
  checks: HealthCheck[];
}

export const healthKeys = {
  all: ['health'] as const,
};

export function fetchHealth(): Promise<HealthReport> {
  return apiFetch<HealthReport>('/q/health', { acceptStatuses: [503] });
}

export function useBackendHealth() {
  return useQuery({
    queryKey: healthKeys.all,
    queryFn: fetchHealth,
    refetchInterval: 30_000,
  });
}
