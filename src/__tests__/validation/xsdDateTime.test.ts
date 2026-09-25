import { describe, expect, it } from '@jest/globals';
import { parseXsdDateTime } from '../../validation/xsdDateTime';

describe('parseXsdDateTime', () => {
  it('accepts a UTC instant', () => {
    expect(parseXsdDateTime('2026-08-15T10:30:00Z')?.toISOString()).toBe(
      '2026-08-15T10:30:00.000Z',
    );
  });

  it('accepts fractional seconds', () => {
    expect(parseXsdDateTime('2026-08-15T10:30:00.250Z')?.toISOString()).toBe(
      '2026-08-15T10:30:00.250Z',
    );
  });

  it('accepts a positive and a negative offset', () => {
    expect(parseXsdDateTime('2026-08-15T12:30:00+02:00')?.toISOString()).toBe(
      '2026-08-15T10:30:00.000Z',
    );
    expect(parseXsdDateTime('2026-08-15T08:30:00-02:00')?.toISOString()).toBe(
      '2026-08-15T10:30:00.000Z',
    );
  });

  // Date.parse normalises this into 2 March rather than rejecting it. The
  // calendar round-trip is the only thing that catches it.
  it('refuses a day that does not exist in its month', () => {
    expect(parseXsdDateTime('2026-02-30T00:00:00Z')).toBeNull();
    expect(parseXsdDateTime('2026-04-31T12:00:00Z')).toBeNull();
  });

  // The mirror of the case above: a real leap day must survive, so nobody
  // "fixes" the rule with a flat 28-day February.
  it('accepts a genuine leap day', () => {
    expect(parseXsdDateTime('2028-02-29T00:00:00Z')).not.toBeNull();
  });

  it('refuses an offset outside ±14:00', () => {
    expect(parseXsdDateTime('2026-08-15T10:30:00+99:99')).toBeNull();
    expect(parseXsdDateTime('2026-08-15T10:30:00+15:00')).toBeNull();
    expect(parseXsdDateTime('2026-08-15T10:30:00+05:99')).toBeNull();
  });

  it('refuses 14:01 but accepts the legal maximum and minimum', () => {
    expect(parseXsdDateTime('2026-08-15T10:30:00+14:01')).toBeNull();
    expect(parseXsdDateTime('2026-08-15T10:30:00+14:00')).not.toBeNull();
    expect(parseXsdDateTime('2026-08-15T10:30:00-14:00')).not.toBeNull();
  });

  // An in-range hour with a non-zero minute: without this the "hour 14 implies
  // minute 0" half of the rule can be deleted unnoticed.
  it('accepts a non-zero offset minute below the maximum hour', () => {
    expect(parseXsdDateTime('2026-08-15T10:30:00+05:30')).not.toBeNull();
  });

  it('refuses an out-of-range time of day', () => {
    expect(parseXsdDateTime('2026-08-15T24:00:00Z')).toBeNull();
    expect(parseXsdDateTime('2026-08-15T10:60:00Z')).toBeNull();
  });

  it('refuses shapes that are not xsd:dateTime at all', () => {
    for (const bad of [
      '2026-08-15',
      '15/08/2026',
      'Aug 15 2026',
      '',
      'not-a-date',
    ]) {
      expect(parseXsdDateTime(bad)).toBeNull();
    }
  });

  it('refuses a missing value without throwing', () => {
    expect(parseXsdDateTime(null)).toBeNull();
    expect(parseXsdDateTime(undefined)).toBeNull();
  });
});
