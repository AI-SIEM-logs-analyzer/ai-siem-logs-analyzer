import { ApiError } from '@/lib/api-client';
import { errorMessage } from '@/lib/errors';

export function overviewErrorMessage(error: Error, what: string): string {
  if (error instanceof ApiError && error.status === 503) {
    return 'The search index is unreachable, so events cannot be counted. Ingestion continues.';
  }
  return errorMessage(error, what);
}
