import { afterEach, describe, expect, it, vi } from 'vitest';
import { fetchAttackDataset, fetchAttackTechniques } from '@/api/attack';
import { fetchAlertsForMatrix } from '@/api/alerts';
import { apiClient } from '@/api/client';

describe('attack and matrix alerts API helpers', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('requests all techniques when inUseOnly is false', async () => {
    const getSpy = vi.spyOn(apiClient, 'GET').mockResolvedValue({
      data: [
        {
          id: 'T1110',
          name: 'Brute Force',
          subTechnique: false,
          inUse: true,
          platforms: [],
          tactics: [],
        },
      ],
      error: undefined,
      response: new Response(),
    });

    const result = await fetchAttackTechniques({ inUseOnly: false });
    expect(result).toHaveLength(1);
    expect(getSpy).toHaveBeenCalledWith('/api/attack/techniques', {
      params: { query: { inUse: false } },
      signal: undefined,
    });
  });

  it('fetches dataset metadata from /api/attack/dataset', async () => {
    vi.spyOn(apiClient, 'GET').mockResolvedValue({
      data: { version: '19.2', domain: 'enterprise-attack', tacticCount: 14, techniqueCount: 693 },
      error: undefined,
      response: new Response(),
    });

    const dataset = await fetchAttackDataset();
    expect(dataset.version).toBe('19.2');
    expect(dataset.tacticCount).toBe(14);
  });

  it('fetches remaining alert pages up to MAX_MATRIX_ALERT_PAGES when totalPages > 1', async () => {
    const getSpy = vi.spyOn(apiClient, 'GET').mockImplementation(((
      _url: string,
      init?: { params?: { query?: { page?: number } } },
    ) => {
      const page = init?.params?.query?.page ?? 0;
      return Promise.resolve({
        data: {
          items: [
            {
              id: `alert-${page}`,
              severity: 'HIGH',
              status: 'NEW',
              title: `Alert ${page}`,
              createdAt: '2026-04-12T10:00:00Z',
              eventCount: 1,
              techniques: [],
            },
          ],
          page,
          size: 100,
          totalElements: 200,
          totalPages: 2,
        },
        error: undefined,
        response: new Response(),
      });
    }) as never);

    const alerts = await fetchAlertsForMatrix({ severity: ['HIGH'], status: ['NEW'] });
    expect(alerts.map((a) => a.id)).toEqual(['alert-0', 'alert-1']);
    expect(getSpy).toHaveBeenCalledTimes(2);
  });
});
