import { Suspense, useEffect, useMemo, useState } from 'react';
import { Grid3x3, RotateCcw, ShieldCheck } from 'lucide-react';
import { useNavigate, useSearchParams } from 'react-router';
import { useAlertsForMatrix } from '@/api/alerts';
import {
  useAttackDataset,
  useAttackTactics,
  useAttackTechniques,
  useTechniquesInUse,
} from '@/api/attack';
import {
  attackMatrixChartHeight,
  attackMatrixColors,
  attackMatrixOption,
} from '@/components/attack/attack-matrix-option';
import { prefersDark } from '@/components/charts/chart-theme';
import { LazyEChart } from '@/components/charts/lazy-echart';
import { ErrorState } from '@/components/feedback/error-state';
import { PageHeader } from '@/components/page-header';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { ALERT_STATUSES, ALERT_STATUS_LABELS, toggle, type AlertStatus } from '@/lib/alert-filters';
import {
  buildAttackMatrix,
  hasMatrixFilters,
  matrixCellAlertsParams,
  matrixFiltersToParams,
  parseMatrixFilters,
  type MatrixFilters,
  type MatrixScope,
  type Severity,
} from '@/lib/attack-matrix';
import { SEVERITIES } from '@/lib/event-filters';
import { formatLevel } from '@/lib/heatmap';

// Narrowest a tactic column gets before its two-line label and cell names stop fitting.
const MATRIX_COLUMN_MIN_WIDTH = 116;

const SEVERITY_LABELS: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  ERROR: 'Error',
  MEDIUM: 'Medium',
  WARNING: 'Warning',
  LOW: 'Low',
  INFO: 'Info',
  DEBUG: 'Debug',
};

function formatMatrixLevel(
  levels: [number, number, number, number],
  maxAlertCount: number,
  lvl: 1 | 2 | 3 | 4,
): string {
  const idx = lvl - 1;
  const from = levels[idx];
  const to = idx < 3 ? Math.max(from, levels[idx + 1] - 1) : Math.max(from, maxAlertCount);
  return formatLevel({ from, to }, String);
}

function useIsDark(): boolean {
  const [isDark, setIsDark] = useState(() => prefersDark());
  useEffect(() => {
    if (typeof MutationObserver === 'undefined') return;
    const observer = new MutationObserver(() => setIsDark(prefersDark()));
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
    return () => observer.disconnect();
  }, []);
  return isDark;
}

export function AttackMatrixPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const isDark = useIsDark();

  const filters = useMemo(() => parseMatrixFilters(searchParams), [searchParams]);
  const updateFilters = (next: MatrixFilters) => {
    setSearchParams(matrixFiltersToParams(next), { replace: true });
  };

  const tacticsQuery = useAttackTactics();
  const techniquesQuery = useAttackTechniques({
    inUseOnly: filters.scope === 'active' ? true : false,
  });
  const inUseQuery = useTechniquesInUse();
  const datasetQuery = useAttackDataset();
  const alertsQuery = useAlertsForMatrix({
    severity: filters.severity,
    status: filters.status,
  });

  const inUseIds = useMemo(
    () =>
      new Set((inUseQuery.data ?? []).map((t) => t.id).filter((id): id is string => Boolean(id))),
    [inUseQuery.data],
  );

  const isLoading =
    tacticsQuery.isLoading ||
    techniquesQuery.isLoading ||
    alertsQuery.isLoading ||
    inUseQuery.isLoading;
  const error =
    tacticsQuery.error ?? techniquesQuery.error ?? alertsQuery.error ?? inUseQuery.error;

  const matrix = useMemo(
    () =>
      buildAttackMatrix(
        tacticsQuery.data ?? [],
        techniquesQuery.data ?? [],
        alertsQuery.data ?? [],
        filters.scope,
        inUseIds,
      ),
    [tacticsQuery.data, techniquesQuery.data, alertsQuery.data, filters.scope, inUseIds],
  );

  const option = useMemo(() => attackMatrixOption(matrix, isDark), [matrix, isDark]);
  const palette = useMemo(() => attackMatrixColors(isDark), [isDark]);
  const chartHeight = attackMatrixChartHeight(matrix.maxColumnDepth);

  const handleScopeChange = (scope: MatrixScope) => {
    updateFilters({ ...filters, scope });
  };

  const handleToggleSeverity = (sev: Severity) => {
    updateFilters({ ...filters, severity: toggle(filters.severity, sev) });
  };

  const handleToggleStatus = (st: AlertStatus) => {
    updateFilters({ ...filters, status: toggle(filters.status, st) });
  };

  const handleCellClick = ({ colIndex, rowIndex }: { colIndex: number; rowIndex: number }) => {
    const cell = matrix.cells.find((c) => c.tacticIndex === colIndex && c.rowIndex === rowIndex);
    if (!cell) return;
    const params = matrixCellAlertsParams(cell, filters);
    void navigate({ pathname: '/alerts', search: `?${params.toString()}` });
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="MITRE ATT&CK Navigator"
        description="Enterprise ATT&CK tactic-by-technique coverage and active detection density matrix. Click any cell to inspect matching alerts."
        actions={
          datasetQuery.data ? (
            <Badge variant="outline" className="gap-1.5 py-1 text-xs">
              <ShieldCheck className="h-3.5 w-3.5 text-sky-500" />
              Enterprise ATT&CK v{datasetQuery.data.version} · {datasetQuery.data.techniqueCount}{' '}
              techniques
            </Badge>
          ) : null
        }
      />

      <Card>
        <CardContent className="flex flex-wrap items-center justify-between gap-3 pt-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-1 rounded-md border p-1">
              <Button
                type="button"
                size="sm"
                variant={filters.scope === 'active' ? 'default' : 'ghost'}
                onClick={() => handleScopeChange('active')}
              >
                Covered & active
              </Button>
              <Button
                type="button"
                size="sm"
                variant={filters.scope === 'all' ? 'default' : 'ghost'}
                onClick={() => handleScopeChange('all')}
              >
                Full Enterprise matrix
              </Button>
            </div>

            <div className="flex flex-wrap items-center gap-1">
              <span className="text-muted-foreground mr-1 text-xs font-medium">Severity:</span>
              {SEVERITIES.map((sev) => {
                const active = filters.severity.includes(sev);
                return (
                  <Button
                    key={sev}
                    type="button"
                    size="sm"
                    variant={active ? 'default' : 'outline'}
                    aria-pressed={active}
                    onClick={() => handleToggleSeverity(sev)}
                  >
                    {SEVERITY_LABELS[sev]}
                  </Button>
                );
              })}
            </div>

            <div className="flex flex-wrap items-center gap-1">
              <span className="text-muted-foreground mr-1 text-xs font-medium">Status:</span>
              {ALERT_STATUSES.map((st) => {
                const active = filters.status.includes(st);
                return (
                  <Button
                    key={st}
                    type="button"
                    size="sm"
                    variant={active ? 'default' : 'outline'}
                    aria-pressed={active}
                    onClick={() => handleToggleStatus(st)}
                  >
                    {ALERT_STATUS_LABELS[st]}
                  </Button>
                );
              })}
            </div>
          </div>

          {hasMatrixFilters(filters) && (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={() => updateFilters({ severity: [], status: [], scope: 'active' })}
            >
              <RotateCcw className="mr-1.5 h-3.5 w-3.5" />
              Reset filters
            </Button>
          )}
        </CardContent>
      </Card>

      {error ? (
        <ErrorState
          what="the ATT&CK matrix"
          error={error}
          onRetry={() => {
            void tacticsQuery.refetch();
            void techniquesQuery.refetch();
            void inUseQuery.refetch();
            void alertsQuery.refetch();
          }}
        />
      ) : isLoading ? (
        <Card>
          <CardHeader>
            <Skeleton className="h-5 w-48" />
            <Skeleton className="h-4 w-72" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-80 w-full" />
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle className="flex items-center gap-2 text-base">
                <Grid3x3 className="text-muted-foreground h-4 w-4" />
                Technique Detection Matrix
              </CardTitle>
              <CardDescription>
                {matrix.totalCoveredTechniques} rule-covered parent technique
                {matrix.totalCoveredTechniques === 1 ? '' : 's'} · {matrix.totalDetectedTechniques}{' '}
                with active detections · {matrix.totalAlertHits} alert hit
                {matrix.totalAlertHits === 1 ? '' : 's'}
                {matrix.peakCell
                  ? ` · Peak: ${matrix.peakCell.techniqueId} (${matrix.peakCell.alertCount})`
                  : ''}
              </CardDescription>
            </div>

            <div className="text-muted-foreground flex flex-wrap items-center gap-2 text-xs">
              <span className="inline-flex items-center gap-1.5">
                <span
                  className="inline-block h-3 w-3 rounded-xs border"
                  style={{
                    backgroundColor: palette.uncoveredFill,
                    borderColor: palette.uncoveredBorder,
                  }}
                />
                Uncovered
              </span>
              <span className="inline-flex items-center gap-1.5">
                <span
                  className="inline-block h-3 w-3 rounded-xs border"
                  style={{
                    backgroundColor: palette.coveredFill,
                    borderColor: palette.coveredBorder,
                  }}
                />
                Rule-covered (0)
              </span>
              {([1, 2, 3, 4] as const).map((lvl) => (
                <span key={lvl} className="inline-flex items-center gap-1.5">
                  <span
                    className="inline-block h-3 w-3 rounded-xs border"
                    style={{
                      backgroundColor: palette.detectedFills[lvl - 1],
                      borderColor: palette.detectedBorders[lvl - 1],
                    }}
                  />
                  {matrix.maxAlertCount > 0
                    ? formatMatrixLevel(matrix.levels, matrix.maxAlertCount, lvl)
                    : `L${lvl}`}
                </span>
              ))}
            </div>
          </CardHeader>

          <CardContent>
            {matrix.cells.length === 0 ? (
              <div className="text-muted-foreground flex flex-col items-center justify-center gap-3 py-12 text-center text-sm">
                <p>No techniques match the current matrix scope.</p>
                {filters.scope === 'active' && (
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => handleScopeChange('all')}
                  >
                    Show Full Enterprise matrix
                  </Button>
                )}
              </div>
            ) : (
              <div className="overflow-x-auto">
                {/* Wide enough for every column's label; the full matrix scrolls sideways. */}
                <div style={{ minWidth: matrix.tactics.length * MATRIX_COLUMN_MIN_WIDTH }}>
                  <Suspense
                    fallback={<Skeleton className="w-full" style={{ height: chartHeight }} />}
                  >
                    <LazyEChart
                      option={option}
                      height={chartHeight}
                      ariaLabel="MITRE ATT&CK technique detection matrix"
                      onCellClick={handleCellClick}
                    />
                  </Suspense>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
