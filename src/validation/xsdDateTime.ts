/**
 * Parsing an `xsd:dateTime` strictly enough to trust the result.
 *
 * `Date.parse` is not this. It normalises `2026-02-30` into 2 March instead of
 * rejecting it, and it will read a timezone offset no calendar has. Both traps
 * were found in `@mcp-abap-adt/auth-mocks` and fixed there the same way: match
 * the lexical shape, then require every component to survive a round trip.
 *
 * Deliberately not implemented: negative (BCE) years, the `24:00:00`
 * end-of-day form, and leap seconds. No identity provider in this family emits
 * them, and pretending to cover them would be worse than saying so.
 */

const SHAPE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/** Returns the instant, or null when the value is not a valid xsd:dateTime. */
export function parseXsdDateTime(
  value: string | null | undefined,
): Date | null {
  if (!value) return null;
  const m = SHAPE.exec(value);
  if (!m) return null;

  const [, y, mo, d, h, mi, s, fraction, zone] = m;
  const year = Number(y);
  const month = Number(mo);
  const day = Number(d);
  const hour = Number(h);
  const minute = Number(mi);
  const second = Number(s);

  if (month < 1 || month > 12) return null;
  if (hour > 23 || minute > 59 || second > 59) return null;

  // The calendar round trip. Date.UTC rolls 2026-02-30 into 2026-03-02, so a
  // component that comes back changed means the date does not exist.
  const utc = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    utc.getUTCFullYear() !== year ||
    utc.getUTCMonth() !== month - 1 ||
    utc.getUTCDate() !== day
  ) {
    return null;
  }

  if (zone !== 'Z') {
    const offsetHour = Number(zone.slice(1, 3));
    const offsetMinute = Number(zone.slice(4, 6));
    // xsd:dateTime bounds the offset at ±14:00, and exactly 14 allows no
    // minutes. Both halves matter: +15:00 fails the first, +14:01 the second.
    if (offsetHour > 14 || offsetMinute > 59) return null;
    if (offsetHour === 14 && offsetMinute !== 0) return null;
  }

  const parsed = new Date(
    `${y}-${mo}-${d}T${h}:${mi}:${s}${fraction ?? ''}${zone}`,
  );
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}
