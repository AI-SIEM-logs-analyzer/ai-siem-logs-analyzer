import { fieldGroups, fieldText } from '@/lib/event-fields';

describe('fieldText', () => {
  it('reads scalars and skips what is missing or nested', () => {
    const fields = { status: 404, host: 'web-1', uaBot: false, empty: '', nested: { a: 1 } };
    expect(fieldText(fields, 'status')).toBe('404');
    expect(fieldText(fields, 'host')).toBe('web-1');
    expect(fieldText(fields, 'uaBot')).toBe('false');
    expect(fieldText(fields, 'empty')).toBeUndefined();
    expect(fieldText(fields, 'nested')).toBeUndefined();
    expect(fieldText(undefined, 'host')).toBeUndefined();
  });
});

describe('fieldGroups', () => {
  it('lays the fields out in groups, marks the ones a click can filter on, and keeps the rest', () => {
    const groups = fieldGroups({
      srcIp: '203.0.113.7',
      host: 'web-1',
      status: 503,
      method: 'GET',
      bytes: 1234,
      geoAsn: 64500,
      uaBot: true,
      customThing: 'x',
    });
    expect(groups.map((group) => group.title)).toEqual([
      'Origin',
      'HTTP request',
      'Location',
      'Client',
      'Other fields',
    ]);
    expect(groups[0].rows).toEqual([
      { key: 'host', label: 'Host', value: 'web-1', mono: true },
      { key: 'srcIp', label: 'Source IP', value: '203.0.113.7', drill: 'srcIp', mono: true },
    ]);
    expect(groups[1].rows.find((row) => row.key === 'status')).toMatchObject({
      value: '503',
      drill: 'status',
    });
    expect(groups[2].rows[0].value).toBe('AS64500');
    expect(groups[3].rows[0]).toMatchObject({ label: 'Bot', value: 'Yes' });
    expect(groups[4].rows).toEqual([{ key: 'customThing', label: 'Custom thing', value: 'x' }]);
  });

  it('leaves out empty groups', () => {
    expect(fieldGroups({})).toEqual([]);
    expect(fieldGroups(undefined)).toEqual([]);
  });
});
