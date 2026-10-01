import { ApiError } from '@/lib/api-client';

/** Why a dashboard card has nothing to show; `what` names the card ("the event timeline"). */
export function overviewErrorMessage(error: Error, what: string): string {
  if (error instanceof ApiError && error.status === 503) {
    return 'The search index is unreachable, so events cannot be counted. Ingestion continues.';
  }
  return `Could not load ${what}: ${error.message}`;
}
