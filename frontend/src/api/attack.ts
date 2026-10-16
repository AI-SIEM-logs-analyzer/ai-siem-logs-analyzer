import { useQuery } from '@tanstack/react-query';
import { apiClient, unwrap } from '@/api/client';
import type { components } from '@/api/schema';
import { isSubTechnique } from '@/lib/attack-matrix';

export type AttackTactic = components['schemas']['AttackTacticResponse'] & {
  shortName?: string;
  matrixOrder?: number;
};

export type AttackTechnique = Omit<components['schemas']['AttackTechniqueResponse'], 'tactics'> & {
  subTechnique?: boolean;
  inUse?: boolean;
  deprecated?: boolean;
  revoked?: boolean;
  platforms?: string[];
  tactics?: (components['schemas']['AttackTacticRefResponse'] & { shortName?: string })[];
};

export type AttackDataset = components['schemas']['AttackDatasetResponse'] & {
  domain?: string;
  tacticCount?: number;
  source?: string;
};

export type AlertTechnique = components['schemas']['AlertTechniqueResponse'];

export interface AttackTechniquesFilter {
  /** Sent as the backend's `inUse` query param: only techniques an alert can name. */
  inUseOnly?: boolean;
}

const STALE_TIME_MS = 5 * 60_000;

export const attackKeys = {
  tactics: ['attack', 'tactics'] as const,
  techniquesInUse: ['attack', 'techniques', { inUseOnly: true }] as const,
};

export async function fetchAttackTactics(signal?: AbortSignal): Promise<AttackTactic[]> {
  return unwrap(await apiClient.GET('/api/attack/tactics', { signal }));
}

export function useAttackTactics() {
  return useQuery({
    queryKey: ['attack', 'tactics'],
    queryFn: ({ signal }) => fetchAttackTactics(signal),
    staleTime: STALE_TIME_MS,
  });
}

export async function fetchAttackTechniques(
  filter: AttackTechniquesFilter = {},
  signal?: AbortSignal,
): Promise<AttackTechnique[]> {
  const techniques = await unwrap(
    apiClient.GET('/api/attack/techniques', {
      params: filter.inUseOnly !== undefined ? { query: { inUse: filter.inUseOnly } } : undefined,
      signal,
    }),
  );
  // The backend DTO carries neither `subTechnique` nor `inUse`: derive the first from the ID,
  // and with `inUse=true` every technique returned is in use by definition.
  return (techniques ?? []).map((t) => ({
    ...t,
    subTechnique: isSubTechnique(t),
    ...(filter.inUseOnly === true && (t as AttackTechnique).inUse === undefined && { inUse: true }),
  }));
}

export function useAttackTechniques(filter: AttackTechniquesFilter = {}) {
  return useQuery({
    queryKey: ['attack', 'techniques', filter],
    queryFn: ({ signal }) => fetchAttackTechniques(filter, signal),
    staleTime: STALE_TIME_MS,
  });
}

export function useTechniquesInUse() {
  return useQuery({
    queryKey: ['attack', 'techniques', { inUseOnly: true }],
    queryFn: ({ signal }) => fetchAttackTechniques({ inUseOnly: true }, signal),
    staleTime: STALE_TIME_MS,
  });
}

export async function fetchAttackDataset(signal?: AbortSignal): Promise<AttackDataset> {
  return unwrap(await apiClient.GET('/api/attack/dataset', { signal }));
}

export function useAttackDataset() {
  return useQuery({
    queryKey: ['attack', 'dataset'],
    queryFn: ({ signal }) => fetchAttackDataset(signal),
    staleTime: STALE_TIME_MS,
  });
}
