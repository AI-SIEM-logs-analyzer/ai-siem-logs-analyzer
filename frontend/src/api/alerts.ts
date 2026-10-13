import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api } from '@/api/client';
import type { components } from '@/api/schema';
import { unwrap } from '@/lib/api-client';
import type { AlertFilters } from '@/lib/alert-filters';

// /api/alerts: the alerts detection raised, listed for triage and opened one at a time.

export type Alert = components['schemas']['AlertResponse'];
export type AlertEvent = components['schemas']['AlertEventResponse'];
export type AlertPage = components['schemas']['PageResponseAlertResponse'];
export type AlertSummary = components['schemas']['AlertSummaryResponse'];
export type AttackType = components['schemas']['AttackType'];

/** Alerts per page on the alerts page. */
export const ALERT_PAGE_SIZE = 25;

/** How often the alert list asks again, so a new alert shows up without a reload. */
export const ALERTS_REFRESH_MS = 30_000;

export const alertKeys = {
  all: ['alerts'] as const,
  list: (filters: AlertFilters) => ['alerts', 'list', filters] as const,
  detail: (id: number) => ['alerts', 'detail', id] as const,
};

export function fetchAlertPage(filters: AlertFilters, size = ALERT_PAGE_SIZE): Promise<AlertPage> {
  return unwrap(
    api.GET('/api/alerts', {
      params: {
        query: {
          ...(filters.severity.length > 0 && { severity: filters.severity }),
          ...(filters.status.length > 0 && { status: filters.status }),
          page: filters.page,
          size,
        },
      },
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
