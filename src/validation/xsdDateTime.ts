/**
 * Parsing an `xsd:dateTime` strictly enough to trust the result.
 *
 * `Date.parse` is not this. It normalises `2026-02-30` into 2 March instead of
 * rejecting it, and it will read a timezone offset no calendar has. Both traps
 * were found in `@mcp-abap-adt/auth-mocks` and fixed there the same way: match
 * the lexical shape, then require every component to survive a round trip. The
 * instant is computed from the components rather than handed back to `Date`,
 * whose handling of invalid strings is implementation-defined.
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

  // Milliseconds from the fraction: pad to 3 digits and truncate extras.
  // Avoid floating-point multiplication: 0.57 * 1000 = 569.99999….
  const ms = fraction
    ? Number(fraction.slice(1).padEnd(3, '0').slice(0, 3))
    : 0;

  // Offset in milliseconds. For zone Z it is 0. Otherwise apply the sign.
  let offsetMs = 0;
  if (zone !== 'Z') {
    const offsetHour = Number(zone.slice(1, 3));
    const offsetMinute = Number(zone.slice(4, 6));
    // xsd:dateTime bounds the offset at ±14:00, and exactly 14 allows no
    // minutes. Both halves matter: +15:00 fails the first, +14:01 the second.
    if (offsetHour > 14 || offsetMinute > 59) return null;
    if (offsetHour === 14 && offsetMinute !== 0) return null;

    const sign = zone[0] === '-' ? -1 : 1;
    offsetMs = sign * (offsetHour * 60 + offsetMinute) * 60_000;
  }

  // The instant is UTC time + milliseconds - offset, because local time = UTC + offset.
  const instant = utc.getTime() + ms - offsetMs;
  return new Date(instant);
}
