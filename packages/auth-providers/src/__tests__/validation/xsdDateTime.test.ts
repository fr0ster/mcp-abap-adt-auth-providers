import { describe, expect, it } from '@jest/globals';
import { parseXsdDateTime } from '../../validation/xsdDateTime';

describe('parseXsdDateTime', () => {
  it('accepts a UTC instant', () => {
    expect(parseXsdDateTime('2026-08-15T10:30:00Z')?.toISOString()).toBe(
      '2026-08-15T10:30:00.000Z',
    );
  });

  it('accepts fractional seconds and truncates to milliseconds', () => {
    // Standard fraction case
    expect(parseXsdDateTime('2026-08-15T10:30:00.250Z')?.toISOString()).toBe(
      '2026-08-15T10:30:00.250Z',
    );
    // The float trap: 0.57 * 1000 = 569.99999…, so we parse as string digits
    expect(parseXsdDateTime('2026-08-15T10:30:00.57Z')?.toISOString()).toBe(
      '2026-08-15T10:30:00.570Z',
    );
    // Extra digits beyond milliseconds are truncated, not rounded
    expect(parseXsdDateTime('2026-08-15T10:30:00.1239Z')?.toISOString()).toBe(
      '2026-08-15T10:30:00.123Z',
    );
    // Single digit fraction
    expect(parseXsdDateTime('2026-08-15T10:30:00.5Z')?.toISOString()).toBe(
      '2026-08-15T10:30:00.500Z',
    );
  });

  it('accepts a positive and a negative offset', () => {
    expect(parseXsdDateTime('2026-08-15T12:30:00+02:00')?.toISOString()).toBe(
      '2026-08-15T10:30:00.000Z',
    );
    expect(parseXsdDateTime('2026-08-15T08:30:00-02:00')?.toISOString()).toBe(
      '2026-08-15T10:30:00.000Z',
    );
    // Offset with non-zero minutes: positive (India Standard Time +05:30)
    expect(parseXsdDateTime('2026-08-15T15:30:00+05:30')?.toISOString()).toBe(
      '2026-08-15T10:00:00.000Z',
    );
    // Offset with non-zero minutes: negative to catch sign-handling regressions
    expect(parseXsdDateTime('2026-08-15T10:30:00-05:30')?.toISOString()).toBe(
      '2026-08-15T16:00:00.000Z',
    );
    // Zero-hour negative offset with minutes
    expect(parseXsdDateTime('2026-08-15T10:00:00-00:30')?.toISOString()).toBe(
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

  // The shape, read character by character since the regular expression
  // went (no regular expression over document text): each of these differs
  // from a valid value in one place.
  it.each([
    ['a five-digit year', '20260-08-15T10:30:00Z'],
    ['a three-digit year', '026-08-15T10:30:00Z'],
    ['a one-digit month', '2026-8-15T10:30:00Z'],
    ['a lower-case T', '2026-08-15t10:30:00Z'],
    ['a space for T', '2026-08-15 10:30:00Z'],
    ['a lower-case Z', '2026-08-15T10:30:00z'],
    ['no zone', '2026-08-15T10:30:00'],
    ['a fraction point without digits', '2026-08-15T10:30:00.Z'],
    ['a comma for the fraction point', '2026-08-15T10:30:00,5Z'],
    ['a non-ASCII digit', '2026-08-1\u0665T10:30:00Z'],
    ['a full-width digit', '\uff12026-08-15T10:30:00Z'],
    ['an offset without minutes', '2026-08-15T10:30:00+02'],
    ['an offset without its colon', '2026-08-15T10:30:00+0200'],
    ['trailing text', '2026-08-15T10:30:00Zx'],
    ['a trailing newline', '2026-08-15T10:30:00Z\n'],
    ['leading space', ' 2026-08-15T10:30:00Z'],
    ['a sign before the year', '+2026-08-15T10:30:00Z'],
  ])('refuses %s', (_name, value) => {
    expect(parseXsdDateTime(value)).toBeNull();
  });

  it('accepts a long fraction, reading only its first three digits', () => {
    expect(
      parseXsdDateTime('2026-08-15T10:30:00.123456789012Z')?.toISOString(),
    ).toBe('2026-08-15T10:30:00.123Z');
  });

  it('refuses a missing value without throwing', () => {
    expect(parseXsdDateTime(null)).toBeNull();
    expect(parseXsdDateTime(undefined)).toBeNull();
  });
});
