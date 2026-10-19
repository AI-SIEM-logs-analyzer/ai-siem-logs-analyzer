import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api/client';
import type { components } from '@/api/schema';
import { unwrap } from '@/lib/api-client';
import type { AlertFilters } from '@/lib/alert-filters';
import type { Severity } from '@/lib/attack-matrix';

// /api/alerts: the alerts detection raised, listed for triage and opened one at a time.

export type Alert = components['schemas']['AlertResponse'];
export type AlertDetail = Alert;
export type AlertEvent = components['schemas']['AlertEventResponse'];
export type AlertPage = components['schemas']['PageResponseAlertResponse'] & {
  totalPages?: number;
  totalElements?: number;
};
export type AlertSummary = Omit<Alert, 'id' | 'severity' | 'techniques'> &
  Partial<Omit<components['schemas']['AlertSummaryResponse'], 'severity'>> & {
    id?: number | string;
    severity?: Severity;
    createdAt?: string;
    techniques?: (Omit<components['schemas']['AlertTechniqueResponse'], 'tactics'> & {
      tactics?: (components['schemas']['AttackTacticRefResponse'] & { shortName?: string })[];
    })[];
  };
export type AttackType = components['schemas']['AttackType'];

/** Alerts per page on the alerts page. */
export const ALERT_PAGE_SIZE = 25;

/** How often the alert list asks again, so a new alert shows up without a reload. */
export const ALERTS_REFRESH_MS = 30_000;
export const ALERTS_POLL_INTERVAL_MS = ALERTS_REFRESH_MS;

export const alertKeys = {
  all: ['alerts'] as const,
  list: (filters: AlertFilters) => ['alerts', 'list', filters] as const,
  detail: (id: number) => ['alerts', 'detail', id] as const,
};

export function fetchAlertPage(
  filters: AlertFilters & { size?: number },
  sizeOrSignal: number | AbortSignal = ALERT_PAGE_SIZE,
): Promise<AlertPage> {
  const size = typeof sizeOrSignal === 'number' ? sizeOrSignal : (filters.size ?? ALERT_PAGE_SIZE);
  const signal = typeof sizeOrSignal === 'number' ? undefined : sizeOrSignal;
  return unwrap(
    api.GET('/api/alerts', {
      params: {
        query: {
          ...(filters.severity.length > 0 && { severity: filters.severity }),
          ...(filters.status.length > 0 && { status: filters.status }),
          ...(filters.technique.length > 0 && { technique: filters.technique }),
          ...(filters.tactic.length > 0 && { tactic: filters.tactic }),
          page: filters.page,
          size,
        },
      },
      signal,
    }),
  );
}

/** A page of the alert list, kept on screen while another page or filter loads. */
export function useAlertPage(filters: AlertFilters) {
  return useQuery({
    queryKey: alertKeys.list(filters),
    queryFn: () => fetchAlertPage(filters),
    placeholderData: keepPreviousData,
    refetchInterval: ALERTS_REFRESH_MS,
  });
}

export function fetchAlert(id: number): Promise<Alert> {
  return unwrap(api.GET('/api/alerts/{id}', { params: { path: { id } } }));
}

export function useAlert(id: number) {
  return useQuery({
    queryKey: alertKeys.detail(id),
    queryFn: () => fetchAlert(id),
    enabled: Number.isSafeInteger(id) && id > 0,
  });
}

/** Has the backend's LLM summarise alert `id`; resolves to the alert with its new summary. */
export function summarizeAlert(id: number): Promise<Alert> {
  return unwrap(api.POST('/api/alerts/{id}/summary', { params: { path: { id } } }));
}

/**
 * Asks for a fresh summary of alert `id`. The answer replaces the cached alert, so the page shows
 * it without a second request, and the list refetches to pick it up too.
 */
export function useSummarizeAlert(id: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => summarizeAlert(id),
    onSuccess: (alert) => {
      queryClient.setQueryData(alertKeys.detail(id), alert);
      void queryClient.invalidateQueries({ queryKey: [...alertKeys.all, 'list'] });
    },
  });
}

export type MatrixAlertFilters = {
  severity: Severity[];
  status: AlertFilters['status'];
};

export const MAX_MATRIX_ALERT_PAGES = 5;
const MATRIX_PAGE_SIZE = 100;

export async function fetchAlertsForMatrix(
  filters: MatrixAlertFilters,
  signal?: AbortSignal,
): Promise<AlertSummary[]> {
  const baseFilters = {
    severity: filters.severity as AlertFilters['severity'],
    status: filters.status,
    technique: [] as string[],
    tactic: [] as string[],
    page: 0,
    size: MATRIX_PAGE_SIZE,
  };
  const firstPage = await fetchAlertPage(baseFilters, signal);
  const items: AlertSummary[] = [...(firstPage.items ?? [])];
  const computedPages =
    firstPage.totalPages ??
    (firstPage.total !== undefined && firstPage.size
      ? Math.ceil(firstPage.total / firstPage.size)
      : 1);
  const totalPages = Math.min(computedPages, MAX_MATRIX_ALERT_PAGES);
  if (totalPages <= 1) return items;

  const remainingPages = await Promise.all(
    Array.from({ length: totalPages - 1 }, (_, i) =>
      fetchAlertPage({ ...baseFilters, page: i + 1 }, signal),
    ),
  );
  for (const page of remainingPages) {
    if (page.items) items.push(...page.items);
  }
  return items;
}

export function useAlertsForMatrix(filters: MatrixAlertFilters) {
  return useQuery({
    queryKey: ['alerts', 'matrix', filters],
    queryFn: ({ signal }) => fetchAlertsForMatrix(filters, signal),
    placeholderData: keepPreviousData,
    refetchInterval: ALERTS_POLL_INTERVAL_MS,
  });
}
