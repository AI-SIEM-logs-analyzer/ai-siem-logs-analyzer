import { describe, expect, it } from 'vitest';
import type { AttackTactic, AttackTechnique } from '@/api/attack';
import type { AlertSummary } from '@/api/alerts';
import {
  buildAttackMatrix,
  hasMatrixFilters,
  matrixCellAlertsParams,
  matrixFiltersToParams,
  parseMatrixFilters,
} from '@/lib/attack-matrix';

const TACTICS: AttackTactic[] = [
  {
    id: 'TA0006',
    shortName: 'credential-access',
    name: 'Credential Access',
    matrixOrder: 6,
    url: 'https://attack.mitre.org/tactics/TA0006',
  },
  {
    id: 'TA0001',
    shortName: 'initial-access',
    name: 'Initial Access',
    matrixOrder: 1,
    url: 'https://attack.mitre.org/tactics/TA0001',
  },
];

const TECHNIQUES: AttackTechnique[] = [
  {
    id: 'T1190',
    name: 'Exploit Public-Facing Application',
    subTechnique: false,
    inUse: true,
    deprecated: false,
    revoked: false,
    platforms: ['Linux'],
    tactics: [{ id: 'TA0001', shortName: 'initial-access', name: 'Initial Access' }],
  },
  {
    id: 'T1110',
    name: 'Brute Force',
    subTechnique: false,
    inUse: true,
    deprecated: false,
    revoked: false,
    platforms: ['Linux'],
    tactics: [{ id: 'TA0006', shortName: 'credential-access', name: 'Credential Access' }],
  },
  {
    id: 'T1110.001',
    name: 'Password Guessing',
    subTechnique: true,
    parentId: 'T1110',
    inUse: true,
    deprecated: false,
    revoked: false,
    platforms: ['Linux'],
    tactics: [{ id: 'TA0006', shortName: 'credential-access', name: 'Credential Access' }],
  },
  {
    id: 'T1555',
    name: 'Credentials from Password Stores',
    subTechnique: false,
    inUse: false,
    deprecated: false,
    revoked: false,
    platforms: ['Linux'],
    tactics: [{ id: 'TA0006', shortName: 'credential-access', name: 'Credential Access' }],
  },
];

const ALERTS: AlertSummary[] = [
  {
    id: 'a1',
    title: 'SSH Brute Force',
    severity: 'HIGH',
    status: 'NEW',
    createdAt: '2026-04-12T10:00:00Z',
    eventCount: 5,
    techniques: [
      {
        id: 'T1110',
        name: 'Brute Force',
        source: 'RULE',
        tactics: [{ id: 'TA0006', shortName: 'credential-access', name: 'Credential Access' }],
      },
      {
        id: 'T1110.001',
        name: 'Password Guessing',
        source: 'RULE',
        tactics: [{ id: 'TA0006', shortName: 'credential-access', name: 'Credential Access' }],
      },
    ],
  },
  {
    id: 'a2',
    title: 'Second Brute Force',
    severity: 'CRITICAL',
    status: 'NEW',
    createdAt: '2026-04-12T10:05:00Z',
    eventCount: 8,
    techniques: [
      {
        id: 'T1110.001',
        name: 'Password Guessing',
        source: 'AI',
        tactics: [{ id: 'TA0006', shortName: 'credential-access', name: 'Credential Access' }],
      },
    ],
  },
];

describe('buildAttackMatrix', () => {
  it('orders tactics by matrixOrder and folds sub-techniques into parent cell without double-counting an alert', () => {
    const matrix = buildAttackMatrix(TACTICS, TECHNIQUES, ALERTS, 'active');
    expect(matrix.tactics.map((t) => t.id)).toEqual(['TA0001', 'TA0006']);
    expect(matrix.cells).toHaveLength(2);

    const t1190 = matrix.cells.find((c) => c.techniqueId === 'T1190')!;
    expect(t1190.tacticIndex).toBe(0);
    expect(t1190.rowIndex).toBe(0);
    expect(t1190.state).toBe('covered');
    expect(t1190.alertCount).toBe(0);
    expect(t1190.level).toBe(0);

    const t1110 = matrix.cells.find((c) => c.techniqueId === 'T1110')!;
    expect(t1110.tacticIndex).toBe(1);
    expect(t1110.rowIndex).toBe(0);
    expect(t1110.state).toBe('detected');
    expect(t1110.alertCount).toBe(2);
    expect(t1110.highestSeverity).toBe('CRITICAL');
    expect(t1110.sources).toEqual(['RULE', 'AI']);
    expect(t1110.subTechniques).toEqual([
      { id: 'T1110.001', name: 'Password Guessing', inUse: true, alertCount: 2 },
    ]);
    expect(matrix.peakCell?.techniqueId).toBe('T1110');
  });

  it('drops tactics with no covered or detected technique when scope is active', () => {
    const discovery: AttackTactic = {
      id: 'TA0007',
      shortName: 'discovery',
      name: 'Discovery',
      matrixOrder: 7,
    };
    const tactics = [TACTICS[1], discovery, TACTICS[0]];

    const active = buildAttackMatrix(tactics, TECHNIQUES, ALERTS, 'active');
    expect(active.tactics.map((t) => t.id)).toEqual(['TA0001', 'TA0006']);

    expect(active.cells.find((c) => c.techniqueId === 'T1110')!.tacticIndex).toBe(1);

    const all = buildAttackMatrix(tactics, TECHNIQUES, ALERTS, 'all');
    expect(all.tactics.map((t) => t.id)).toEqual(['TA0001', 'TA0006', 'TA0007']);
  });

  it('includes uncovered parent techniques when scope is all', () => {
    const matrix = buildAttackMatrix(TACTICS, TECHNIQUES, ALERTS, 'all');
    const credCells = matrix.cells.filter((c) => c.tacticId === 'TA0006');
    expect(credCells.map((c) => c.techniqueId)).toEqual(['T1110', 'T1555']);
    expect(credCells[1].state).toBe('uncovered');
    expect(credCells[1].rowIndex).toBe(1);
    expect(matrix.maxColumnDepth).toBe(2);
  });

  it('synthesizes a parent cell when an alert references a technique missing from the catalog', () => {
    const alertsWithUnknown: AlertSummary[] = [
      {
        id: 'a3',
        title: 'AI finding',
        severity: 'MEDIUM',
        status: 'NEW',
        createdAt: '2026-04-12T11:00:00Z',
        eventCount: 1,
        techniques: [
          {
            id: 'T1059.004',
            name: 'Unix Shell',
            source: 'AI',
            tactics: [{ id: 'TA0001', shortName: 'initial-access', name: 'Initial Access' }],
          },
        ],
      },
    ];
    const matrix = buildAttackMatrix(TACTICS, TECHNIQUES, alertsWithUnknown, 'active');
    const synth = matrix.cells.find((c) => c.techniqueId === 'T1059');
    expect(synth).toBeDefined();
    expect(synth?.alertCount).toBe(1);
    expect(synth?.state).toBe('detected');
    expect(synth?.subTechniques[0].id).toBe('T1059.004');
  });

  it('preserves input order for tactics when matrixOrder is absent', () => {
    const unorderedTactics: AttackTactic[] = [
      { id: 'TA0043', shortname: 'reconnaissance', name: 'Reconnaissance' },
      { id: 'TA0001', shortname: 'initial-access', name: 'Initial Access' },
    ];

    const matrix = buildAttackMatrix(unorderedTactics, [], [], 'all');
    expect(matrix.tactics.map((t) => t.id)).toEqual(['TA0043', 'TA0001']);
    expect(matrix.tactics[0].shortName).toBe('reconnaissance');
    expect(matrix.tactics[0].matrixOrder).toBe(1);
    expect(matrix.tactics[1].matrixOrder).toBe(2);
  });

  it('folds techniques without explicit subTechnique property into parent using parentId or dot-notation', () => {
    const rawTechniques: AttackTechnique[] = [
      {
        id: 'T1110',
        name: 'Brute Force',
        tactics: [{ id: 'TA0006', name: 'Credential Access' }],
      },
      {
        id: 'T1110.001',
        name: 'Password Guessing',
        parentId: 'T1110',
        tactics: [{ id: 'TA0006', name: 'Credential Access' }],
      },
    ];
    const alert: AlertSummary[] = [
      {
        id: 'a1',
        title: 'Guessing',
        severity: 'HIGH',
        status: 'NEW',
        techniques: [
          {
            id: 'T1110.001',
            name: 'Password Guessing',
            source: 'RULE',
            tactics: [{ id: 'TA0006', name: 'Credential Access' }],
          },
        ],
      },
    ];
    const matrix = buildAttackMatrix(TACTICS, rawTechniques, alert, 'active');
    expect(matrix.cells).toHaveLength(1);
    const parentCell = matrix.cells[0];
    expect(parentCell.techniqueId).toBe('T1110');
    expect(parentCell.alertCount).toBe(1);
    expect(parentCell.subTechniques).toHaveLength(1);
    expect(parentCell.subTechniques[0].id).toBe('T1110.001');
  });

  it('marks technique as covered using inUseIds set when technique lacks inUse property', () => {
    const rawTechniques: AttackTechnique[] = [
      {
        id: 'T1190',
        name: 'Exploit Public-Facing Application',
        tactics: [{ id: 'TA0001', name: 'Initial Access' }],
      },
    ];
    const inUseIds = new Set(['T1190']);
    const matrix = buildAttackMatrix(TACTICS, rawTechniques, [], 'all', inUseIds);
    const cell = matrix.cells.find((c) => c.techniqueId === 'T1190');
    expect(cell?.state).toBe('covered');
    expect(cell?.inUse).toBe(true);
  });
});

describe('matrix URL filter helpers', () => {
  it('round-trips severity, status, and scope through URLSearchParams', () => {
    const params = matrixFiltersToParams({
      severity: ['HIGH', 'CRITICAL'],
      status: ['NEW'],
      scope: 'all',
    });
    expect(parseMatrixFilters(params)).toEqual({
      severity: ['HIGH', 'CRITICAL'],
      status: ['NEW'],
      scope: 'all',
    });
    expect(hasMatrixFilters(parseMatrixFilters(params))).toBe(true);
  });

  it('builds drill-down /alerts query params for a clicked cell', () => {
    const params = matrixCellAlertsParams(
      { techniqueId: 'T1110', tacticId: 'TA0006' },
      { severity: ['HIGH'], status: ['NEW'] },
    );
    expect(params.getAll('technique')).toEqual(['T1110']);
    expect(params.getAll('tactic')).toEqual(['TA0006']);
    expect(params.getAll('severity')).toEqual(['HIGH']);
    expect(params.getAll('status')).toEqual(['NEW']);
  });
});
