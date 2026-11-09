import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { parseXsdDateTime } from '../../validation/xsdDateTime';
import { cases, caseTitle } from '../helpers/expectations';

describe('parseXsdDateTime', () => {
  it('accepts a UTC instant', () => {
    assert.equal(
      parseXsdDateTime('2026-08-15T10:30:00Z')?.toISOString(),
      '2026-08-15T10:30:00.000Z',
    );
  });

  it('accepts fractional seconds and truncates to milliseconds', () => {
    // Standard fraction case
    assert.equal(
      parseXsdDateTime('2026-08-15T10:30:00.250Z')?.toISOString(),
      '2026-08-15T10:30:00.250Z',
    );
    // The float trap: 0.57 * 1000 = 569.99999…, so we parse as string digits
    assert.equal(
      parseXsdDateTime('2026-08-15T10:30:00.57Z')?.toISOString(),
      '2026-08-15T10:30:00.570Z',
    );
    // Extra digits beyond milliseconds are truncated, not rounded
    assert.equal(
      parseXsdDateTime('2026-08-15T10:30:00.1239Z')?.toISOString(),
      '2026-08-15T10:30:00.123Z',
    );
    // Single digit fraction
    assert.equal(
      parseXsdDateTime('2026-08-15T10:30:00.5Z')?.toISOString(),
      '2026-08-15T10:30:00.500Z',
    );
  });

  it('accepts a positive and a negative offset', () => {
    assert.equal(
      parseXsdDateTime('2026-08-15T12:30:00+02:00')?.toISOString(),
      '2026-08-15T10:30:00.000Z',
    );
    assert.equal(
      parseXsdDateTime('2026-08-15T08:30:00-02:00')?.toISOString(),
      '2026-08-15T10:30:00.000Z',
    );
    // Offset with non-zero minutes: positive (India Standard Time +05:30)
    assert.equal(
      parseXsdDateTime('2026-08-15T15:30:00+05:30')?.toISOString(),
      '2026-08-15T10:00:00.000Z',
    );
    // Offset with non-zero minutes: negative to catch sign-handling regressions
    assert.equal(
      parseXsdDateTime('2026-08-15T10:30:00-05:30')?.toISOString(),
      '2026-08-15T16:00:00.000Z',
    );
    // Zero-hour negative offset with minutes
    assert.equal(
      parseXsdDateTime('2026-08-15T10:00:00-00:30')?.toISOString(),
      '2026-08-15T10:30:00.000Z',
    );
  });

  // Date.parse normalises this into 2 March rather than rejecting it. The
  // calendar round-trip is the only thing that catches it.
  it('refuses a day that does not exist in its month', () => {
    assert.equal(parseXsdDateTime('2026-02-30T00:00:00Z'), null);
    assert.equal(parseXsdDateTime('2026-04-31T12:00:00Z'), null);
  });

  // The mirror of the case above: a real leap day must survive, so nobody
  // "fixes" the rule with a flat 28-day February.
  it('accepts a genuine leap day', () => {
    assert.notEqual(parseXsdDateTime('2028-02-29T00:00:00Z'), null);
  });

  it('refuses an offset outside ±14:00', () => {
    assert.equal(parseXsdDateTime('2026-08-15T10:30:00+99:99'), null);
    assert.equal(parseXsdDateTime('2026-08-15T10:30:00+15:00'), null);
    assert.equal(parseXsdDateTime('2026-08-15T10:30:00+05:99'), null);
  });

  it('refuses 14:01 but accepts the legal maximum and minimum', () => {
    assert.equal(parseXsdDateTime('2026-08-15T10:30:00+14:01'), null);
    assert.notEqual(parseXsdDateTime('2026-08-15T10:30:00+14:00'), null);
    assert.notEqual(parseXsdDateTime('2026-08-15T10:30:00-14:00'), null);
  });

  // An in-range hour with a non-zero minute: without this the "hour 14 implies
  // minute 0" half of the rule can be deleted unnoticed.
  it('accepts a non-zero offset minute below the maximum hour', () => {
    assert.notEqual(parseXsdDateTime('2026-08-15T10:30:00+05:30'), null);
  });

  it('refuses an out-of-range time of day', () => {
    assert.equal(parseXsdDateTime('2026-08-15T24:00:00Z'), null);
    assert.equal(parseXsdDateTime('2026-08-15T10:60:00Z'), null);
  });

  it('refuses shapes that are not xsd:dateTime at all', () => {
    for (const bad of [
      '2026-08-15',
      '15/08/2026',
      'Aug 15 2026',
      '',
      'not-a-date',
    ]) {
      assert.equal(parseXsdDateTime(bad), null);
    }
  });

  // The shape, read character by character since the regular expression
  // went (no regular expression over document text): each of these differs
  // from a valid value in one place.
  for (const [caseIndex, caseRow] of cases([
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
  ]).entries()) {
    const [_name, value] = caseRow;
    it(caseTitle('refuses %s', caseRow, caseIndex), () => {
      assert.equal(parseXsdDateTime(value), null);
    });
  }

  it('accepts a long fraction, reading only its first three digits', () => {
    assert.equal(
      parseXsdDateTime('2026-08-15T10:30:00.123456789012Z')?.toISOString(),
      '2026-08-15T10:30:00.123Z',
    );
  });

  it('refuses a missing value without throwing', () => {
    assert.equal(parseXsdDateTime(null), null);
    assert.equal(parseXsdDateTime(undefined), null);
  });
});
