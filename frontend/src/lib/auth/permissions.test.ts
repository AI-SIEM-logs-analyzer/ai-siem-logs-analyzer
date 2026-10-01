import { can, primaryRole } from './permissions';

describe('can', () => {
  it('lets only an admin manage users', () => {
    expect(can(['ADMIN'], 'users:manage')).toBe(true);
    expect(can(['ANALYST'], 'users:manage')).toBe(false);
    expect(can(['VIEWER'], 'users:manage')).toBe(false);
  });

  it('lets an admin or analyst upload logs, not a viewer', () => {
    expect(can(['ADMIN'], 'logs:upload')).toBe(true);
    expect(can(['ANALYST'], 'logs:upload')).toBe(true);
    expect(can(['VIEWER'], 'logs:upload')).toBe(false);
  });

  it('grants what any one of several roles grants', () => {
    expect(can(['VIEWER', 'ADMIN'], 'users:manage')).toBe(true);
  });

  it('grants nothing without roles', () => {
    expect(can(undefined, 'logs:upload')).toBe(false);
    expect(can([], 'logs:upload')).toBe(false);
  });
});

describe('primaryRole', () => {
  it('picks the most capable role', () => {
    expect(primaryRole(['VIEWER', 'ANALYST'])).toBe('ANALYST');
    expect(primaryRole(undefined)).toBeUndefined();
  });
});
