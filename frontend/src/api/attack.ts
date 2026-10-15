import { useQuery } from '@tanstack/react-query';
import { api } from '@/api/client';
import type { components } from '@/api/schema';
import { unwrap } from '@/lib/api-client';

// /api/attack: the MITRE ATT&CK tactics and techniques alerts are mapped to.

export type AttackTactic = components['schemas']['AttackTacticResponse'];
export type AttackTechnique = components['schemas']['AttackTechniqueResponse'];
export type AlertTechnique = components['schemas']['AlertTechniqueResponse'];

/** The dataset changes only when an administrator imports a release, so a session keeps it. */
const ATTACK_STALE_MS = 60 * 60_000;

export const attackKeys = {
  tactics: ['attack', 'tactics'] as const,
  techniquesInUse: ['attack', 'techniques', 'in-use'] as const,
};

/** Every tactic, in matrix order. */
export function useAttackTactics() {
  return useQuery({
    queryKey: attackKeys.tactics,
    queryFn: () => unwrap(api.GET('/api/attack/tactics')),
    staleTime: ATTACK_STALE_MS,
  });
}

/** The techniques an alert can name: the dozen the filter offers, not the six hundred in ATT&CK. */
export function useTechniquesInUse() {
  return useQuery({
    queryKey: attackKeys.techniquesInUse,
    queryFn: () =>
      unwrap(api.GET('/api/attack/techniques', { params: { query: { inUse: true } } })),
    staleTime: ATTACK_STALE_MS,
  });
}
