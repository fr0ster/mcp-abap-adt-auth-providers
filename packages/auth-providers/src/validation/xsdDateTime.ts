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

/** The ASCII digit at `at`, or -1: never `\\d` widened to other scripts. */
function digitAt(value: string, at: number): number {
  const c = value.charCodeAt(at);
  return c >= 0x30 && c <= 0x39 ? c - 0x30 : -1;
}

/** The `width` ASCII digits starting at `at` as a number, or -1. */
function numberAt(value: string, at: number, width: number): number {
  let n = 0;
  for (let i = 0; i < width; i += 1) {
    const digit = digitAt(value, at + i);
    if (digit < 0) return -1;
    n = n * 10 + digit;
  }
  return n;
}

/** The lexical parts of `YYYY-MM-DDThh:mm:ss[.f+](Z|±hh:mm)`, or null. */
interface Lexical {
  readonly year: number;
  readonly month: number;
  readonly day: number;
  readonly hour: number;
  readonly minute: number;
  readonly second: number;
  /** The fraction's digits, without the point; empty when there is none. */
  readonly fraction: string;
  /** `Z`, or `+hh:mm` / `-hh:mm`. */
  readonly zone: string;
}

/**
 * The shape, read character by character — a value from a SAML document is
 * untrusted, and no regular expression runs over it.
 */
function readLexical(value: string): Lexical | null {
  // YYYY-MM-DDThh:mm:ss is 19 characters, fixed.
  const separators: ReadonlyArray<readonly [number, string]> = [
    [4, '-'],
    [7, '-'],
    [10, 'T'],
    [13, ':'],
    [16, ':'],
  ];
  if (value.length < 20) return null;
  for (const [at, char] of separators) {
    if (value[at] !== char) return null;
  }
  const year = numberAt(value, 0, 4);
  const month = numberAt(value, 5, 2);
  const day = numberAt(value, 8, 2);
  const hour = numberAt(value, 11, 2);
  const minute = numberAt(value, 14, 2);
  const second = numberAt(value, 17, 2);
  if ([year, month, day, hour, minute, second].includes(-1)) return null;

  let at = 19;
  let fraction = '';
  if (value[at] === '.') {
    at += 1;
    const from = at;
    while (digitAt(value, at) >= 0) at += 1;
    if (at === from) return null;
    fraction = value.slice(from, at);
  }

  const zone = value.slice(at);
  if (zone !== 'Z') {
    const sign = zone[0];
    if (zone.length !== 6 || (sign !== '+' && sign !== '-')) return null;
    if (zone[3] !== ':') return null;
    if (numberAt(zone, 1, 2) < 0 || numberAt(zone, 4, 2) < 0) return null;
  }
  return { year, month, day, hour, minute, second, fraction, zone };
}

/** Returns the instant, or null when the value is not a valid xsd:dateTime. */
export function parseXsdDateTime(
  value: string | null | undefined,
): Date | null {
  if (!value) return null;
  const lexical = readLexical(value);
  if (!lexical) return null;
  const { year, month, day, hour, minute, second, fraction, zone } = lexical;

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
  const ms = fraction ? Number(fraction.padEnd(3, '0').slice(0, 3)) : 0;

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
