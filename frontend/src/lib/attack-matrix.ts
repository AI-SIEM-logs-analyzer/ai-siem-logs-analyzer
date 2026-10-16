import type { AlertSummary } from '@/api/alerts';
import type { AttackTactic, AttackTechnique } from '@/api/attack';
import {
  ALERT_STATUSES,
  alertFiltersToParams,
  type AlertFilters,
  type AlertStatus,
} from '@/lib/alert-filters';
import { densityLevels } from '@/lib/heatmap';

export type Severity =
  'CRITICAL' | 'ERROR' | 'WARNING' | 'INFO' | 'DEBUG' | 'HIGH' | 'MEDIUM' | 'LOW';

export type MatrixScope = 'active' | 'all';
export type CellState = 'uncovered' | 'covered' | 'detected';

export interface MatrixFilters {
  severity: Severity[];
  status: AlertStatus[];
  scope: MatrixScope;
}

export interface SubTechniqueSummary {
  id: string;
  name: string;
  inUse: boolean;
  alertCount: number;
}

export interface MatrixCell {
  tacticId: string;
  tacticName: string;
  tacticIndex: number;
  rowIndex: number;
  techniqueId: string;
  name: string;
  url?: string;
  inUse: boolean;
  alertCount: number;
  highestSeverity: Severity | null;
  sources: ('RULE' | 'AI')[];
  state: CellState;
  level: 0 | 1 | 2 | 3 | 4;
  subTechniques: SubTechniqueSummary[];
}

export interface MatrixTacticSummary {
  id: string;
  shortName: string;
  name: string;
  matrixOrder: number;
  url?: string;
  totalTechniques: number;
  coveredTechniques: number;
  detectedTechniques: number;
  alertCount: number;
}

export interface AttackMatrix {
  tactics: MatrixTacticSummary[];
  cells: MatrixCell[];
  maxColumnDepth: number;
  maxAlertCount: number;
  levels: [number, number, number, number];
  totalCoveredTechniques: number;
  totalDetectedTechniques: number;
  totalAlertHits: number;
  peakCell: MatrixCell | null;
}

export const ALL_SEVERITIES: readonly Severity[] = [
  'CRITICAL',
  'HIGH',
  'ERROR',
  'MEDIUM',
  'WARNING',
  'LOW',
  'INFO',
  'DEBUG',
];

const SEVERITY_RANK: Record<Severity, number> = {
  DEBUG: 0,
  INFO: 1,
  LOW: 1,
  WARNING: 2,
  MEDIUM: 2,
  ERROR: 3,
  HIGH: 3,
  CRITICAL: 4,
};

export function isSeverity(value: string): value is Severity {
  return (ALL_SEVERITIES as readonly string[]).includes(value);
}

export function isAlertStatus(value: string): value is AlertStatus {
  return (ALERT_STATUSES as readonly string[]).includes(value);
}

/** Whether `t` is a sub-technique; the backend DTO carries only `parentId`, not `subTechnique`. */
export function isSubTechnique(
  t: Pick<AttackTechnique, 'id' | 'parentId' | 'subTechnique'>,
): boolean {
  return t.subTechnique ?? (Boolean(t.parentId) || (t.id ?? '').includes('.'));
}

function parentIdOf(id: string, explicitParentId?: string): string {
  if (explicitParentId) return explicitParentId;
  const dot = id.indexOf('.');
  return dot > 0 ? id.slice(0, dot) : id;
}

function higherSeverity(a: Severity | null, b: Severity | undefined): Severity | null {
  if (!b) return a;
  if (!a) return b;
  return SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a;
}

function matrixLevels(maxAlertCount: number): [number, number, number, number] {
  const bands = densityLevels(maxAlertCount, 4);
  if (bands.length === 0) return [1, 2, 3, 4];
  const thresholds = bands.map((b) => b.from);
  while (thresholds.length < 4) {
    thresholds.push(thresholds[thresholds.length - 1] ?? 1);
  }
  return [thresholds[0], thresholds[1], thresholds[2], thresholds[3]];
}

function bandForCount(count: number, levels: [number, number, number, number]): 0 | 1 | 2 | 3 | 4 {
  if (count <= 0) return 0;
  if (count >= levels[3]) return 4;
  if (count >= levels[2]) return 3;
  if (count >= levels[1]) return 2;
  return 1;
}

export function buildAttackMatrix(
  tactics: AttackTactic[],
  techniques: AttackTechnique[],
  alerts: AlertSummary[],
  scope: MatrixScope = 'active',
  inUseIds?: ReadonlySet<string>,
): AttackMatrix {
  // The backend lists tactics already in matrix order and without `matrixOrder`: sort only
  // when both sides carry one, otherwise keep the input order (Array#sort is stable).
  const orderedTactics = [...tactics].sort((a, b) =>
    a.matrixOrder !== undefined && b.matrixOrder !== undefined ? a.matrixOrder - b.matrixOrder : 0,
  );
  const tacticById = new Map(orderedTactics.map((t) => [t.id ?? '', t]));
  const isInUse = (tech: AttackTechnique | undefined): boolean =>
    tech !== undefined && (tech.inUse === true || (inUseIds?.has(tech.id ?? '') ?? false));

  const parentsById = new Map<string, AttackTechnique>();
  const subsByParentId = new Map<string, AttackTechnique[]>();

  for (const tech of techniques) {
    const techId = tech.id ?? '';
    if (!techId) continue;
    if (isSubTechnique(tech)) {
      const pid = parentIdOf(techId, tech.parentId);
      const list = subsByParentId.get(pid) ?? [];
      list.push(tech);
      subsByParentId.set(pid, list);
    } else {
      parentsById.set(techId, tech);
    }
  }

  // Track alert hits per (tacticId, parentId) and per (tacticId, subId)
  interface HitAccumulator {
    alertIds: Set<string>;
    highestSeverity: Severity | null;
    sources: Set<'RULE' | 'AI'>;
    subAlerts: Map<string, { name: string; alertIds: Set<string> }>;
    fallbackName?: string;
    fallbackUrl?: string;
  }

  const hitsByCellKey = new Map<string, HitAccumulator>();
  const cellKey = (tacticId: string, parentId: string) => `${tacticId}::${parentId}`;

  for (const alert of alerts) {
    const alertId = String(alert.id ?? `${alert.title ?? ''}-${alert.createdAt ?? ''}`);
    const sev = isSeverity(alert.severity ?? '') ? alert.severity : undefined;

    for (const tech of alert.techniques ?? []) {
      const techId = tech.id ?? '';
      if (!techId) continue;
      const techName = tech.name ?? techId;
      const pid = parentIdOf(techId);
      const isSub = techId !== pid;
      const parentCatalog = parentsById.get(pid);
      const techTactics =
        tech.tactics && tech.tactics.length > 0 ? tech.tactics : (parentCatalog?.tactics ?? []);

      for (const tac of techTactics) {
        const tacId = tac.id ?? '';
        if (!tacticById.has(tacId)) continue;
        const key = cellKey(tacId, pid);
        let acc = hitsByCellKey.get(key);
        if (!acc) {
          acc = {
            alertIds: new Set(),
            highestSeverity: null,
            sources: new Set(),
            subAlerts: new Map(),
            fallbackName: isSub ? (parentCatalog?.name ?? pid) : techName,
            fallbackUrl: tech.url,
          };
          hitsByCellKey.set(key, acc);
        }
        acc.alertIds.add(alertId);
        acc.highestSeverity = higherSeverity(acc.highestSeverity, sev);
        if (tech.source === 'RULE' || tech.source === 'AI') {
          acc.sources.add(tech.source);
        }
        if (isSub) {
          let subAcc = acc.subAlerts.get(techId);
          if (!subAcc) {
            subAcc = { name: techName, alertIds: new Set() };
            acc.subAlerts.set(techId, subAcc);
          }
          subAcc.alertIds.add(alertId);
        }
      }
    }
  }

  // Collect candidate parent IDs per tactic
  const parentsPerTactic = new Map<string, Set<string>>();
  for (const tac of orderedTactics) {
    parentsPerTactic.set(tac.id ?? '', new Set());
  }

  for (const parent of parentsById.values()) {
    const parentId = parent.id ?? '';
    if (!parentId) continue;
    for (const tac of parent.tactics ?? []) {
      parentsPerTactic.get(tac.id ?? '')?.add(parentId);
    }
  }
  for (const [pid, subs] of subsByParentId.entries()) {
    for (const sub of subs) {
      for (const tac of sub.tactics ?? []) {
        parentsPerTactic.get(tac.id ?? '')?.add(pid);
      }
    }
  }
  for (const key of hitsByCellKey.keys()) {
    const [tacticId, pid] = key.split('::');
    parentsPerTactic.get(tacticId)?.add(pid);
  }

  // First pass: build un-leveled cells per tactic column
  const columns: MatrixCell[][] = [];
  let maxAlertCount = 0;

  for (let tacticIndex = 0; tacticIndex < orderedTactics.length; tacticIndex++) {
    const tactic = orderedTactics[tacticIndex];
    const tacticId = tactic.id ?? '';
    const tacticName = tactic.name ?? '';
    const candidateIds = parentsPerTactic.get(tacticId) ?? new Set<string>();
    const colCells: MatrixCell[] = [];

    for (const pid of candidateIds) {
      const parent = parentsById.get(pid);
      const subsInTactic = (subsByParentId.get(pid) ?? []).filter((s) =>
        (s.tactics ?? []).some((t) => (t.id ?? '') === tacticId),
      );
      const acc = hitsByCellKey.get(cellKey(tacticId, pid));
      const alertCount = acc?.alertIds.size ?? 0;
      const inUse = isInUse(parent) || subsInTactic.some(isInUse);
      const isDeprecatedOrRevoked = Boolean(parent?.deprecated || parent?.revoked);

      if (isDeprecatedOrRevoked && !inUse && alertCount === 0) {
        continue;
      }
      if (scope === 'active' && !inUse && alertCount === 0) {
        continue;
      }

      const subMap = new Map<string, SubTechniqueSummary>();
      for (const sub of subsInTactic) {
        const subId = sub.id ?? '';
        if (!subId) continue;
        const subHitCount = acc?.subAlerts.get(subId)?.alertIds.size ?? 0;
        const subInUse = isInUse(sub);
        if (scope === 'all' || subInUse || subHitCount > 0) {
          subMap.set(subId, {
            id: subId,
            name: sub.name ?? subId,
            inUse: subInUse,
            alertCount: subHitCount,
          });
        }
      }
      if (acc) {
        for (const [subId, subAcc] of acc.subAlerts.entries()) {
          if (!subMap.has(subId)) {
            subMap.set(subId, {
              id: subId,
              name: subAcc.name,
              inUse: false,
              alertCount: subAcc.alertIds.size,
            });
          }
        }
      }

      const subTechniques = [...subMap.values()].sort(
        (a, b) => b.alertCount - a.alertCount || a.id.localeCompare(b.id),
      );

      const state: CellState = alertCount > 0 ? 'detected' : inUse ? 'covered' : 'uncovered';

      const sources: ('RULE' | 'AI')[] = [];
      if (acc?.sources.has('RULE')) sources.push('RULE');
      if (acc?.sources.has('AI')) sources.push('AI');

      if (alertCount > maxAlertCount) {
        maxAlertCount = alertCount;
      }

      colCells.push({
        tacticId,
        tacticName,
        tacticIndex,
        rowIndex: 0,
        techniqueId: pid,
        name: parent?.name ?? acc?.fallbackName ?? pid,
        url: parent?.url ?? acc?.fallbackUrl,
        inUse,
        alertCount,
        highestSeverity: acc?.highestSeverity ?? null,
        sources,
        state,
        level: 0,
        subTechniques,
      });
    }

    colCells.sort((a, b) => {
      if (b.alertCount !== a.alertCount) return b.alertCount - a.alertCount;
      if (a.inUse !== b.inUse) return a.inUse ? -1 : 1;
      return a.techniqueId.localeCompare(b.techniqueId);
    });

    colCells.forEach((cell, idx) => {
      cell.rowIndex = idx;
    });

    columns.push(colCells);
  }

  const levels = matrixLevels(maxAlertCount);
  const cells: MatrixCell[] = [];
  const tacticSummaries: MatrixTacticSummary[] = [];
  let maxColumnDepth = 0;
  const coveredSet = new Set<string>();
  const detectedSet = new Set<string>();
  let totalAlertHits = 0;
  let peakCell: MatrixCell | null = null;

  for (let i = 0; i < orderedTactics.length; i++) {
    const tactic = orderedTactics[i];
    const tacticId = tactic.id ?? '';
    const col = columns[i];
    if (col.length > maxColumnDepth) {
      maxColumnDepth = col.length;
    }
    let colCovered = 0;
    let colDetected = 0;
    let colAlerts = 0;

    for (const cell of col) {
      cell.level = bandForCount(cell.alertCount, levels);
      if (cell.inUse) {
        colCovered++;
        coveredSet.add(cell.techniqueId);
      }
      if (cell.alertCount > 0) {
        colDetected++;
        detectedSet.add(cell.techniqueId);
        colAlerts += cell.alertCount;
        totalAlertHits += cell.alertCount;
        if (!peakCell || cell.alertCount > peakCell.alertCount) {
          peakCell = cell;
        }
      }
      cells.push(cell);
    }

    tacticSummaries.push({
      id: tacticId,
      shortName: tactic.shortName ?? tactic.shortname ?? tacticId,
      name: tactic.name ?? '',
      matrixOrder: tactic.matrixOrder ?? i + 1,
      url: tactic.url,
      totalTechniques: col.length,
      coveredTechniques: colCovered,
      detectedTechniques: colDetected,
      alertCount: colAlerts,
    });
  }

  return {
    tactics: tacticSummaries,
    cells,
    maxColumnDepth,
    maxAlertCount,
    levels,
    totalCoveredTechniques: coveredSet.size,
    totalDetectedTechniques: detectedSet.size,
    totalAlertHits,
    peakCell,
  };
}

export function parseMatrixFilters(params: URLSearchParams): MatrixFilters {
  const severity = params.getAll('severity').filter(isSeverity);
  const status = params.getAll('status').filter(isAlertStatus);
  const scope: MatrixScope = params.get('scope') === 'all' ? 'all' : 'active';
  return { severity, status, scope };
}

export function matrixFiltersToParams(filters: MatrixFilters): URLSearchParams {
  const params = new URLSearchParams();
  for (const s of filters.severity) params.append('severity', s);
  for (const s of filters.status) params.append('status', s);
  if (filters.scope === 'all') params.set('scope', 'all');
  return params;
}

export function hasMatrixFilters(filters: MatrixFilters): boolean {
  return filters.severity.length > 0 || filters.status.length > 0 || filters.scope === 'all';
}

export function matrixCellAlertsParams(
  cell: Pick<MatrixCell, 'techniqueId' | 'tacticId'>,
  filters: Pick<MatrixFilters, 'severity' | 'status'>,
): URLSearchParams {
  return alertFiltersToParams({
    severity: filters.severity as AlertFilters['severity'],
    status: filters.status,
    technique: [cell.techniqueId],
    tactic: [cell.tacticId],
    page: 0,
  });
}
