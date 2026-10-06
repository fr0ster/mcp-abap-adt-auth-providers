/**
 * What of an OAuth error response may reach the opt-in `authDebug` line
 * (spec §6) — and nothing else: by default no site reads the server's text.
 *
 * Only RFC 6749 §5.2's `error`, `error_description` and `error_uri`. A token
 * endpoint's body is otherwise untrusted: a misbehaving server can echo the
 * request or return tokens in it, so it is never serialised whole, and every
 * secret the request carried, and anything JWT-shaped, is replaced by its
 * preview (`previewSecret`) — never more than 4 + 4 characters of it.
 */

const ERROR_CAP = 64;
const DESCRIPTION_CAP = 512;

const quote = (value: string, cap: number): string =>
  JSON.stringify(value.length > cap ? `${value.slice(0, cap)}…` : value);

/** Anything shaped like a JWT: three base64url segments, the first a header. */
const JWT_SHAPE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;

/**
 * A value as a server reading it `application/x-www-form-urlencoded` decodes
 * it (RFC 6749 §2.3.1): `+` a space, `%XX` its byte, the whole value — `&`
 * and `=` are part of it, never a separator. Never throws: a malformed escape
 * stays as it is (WHATWG percent-decoding).
 */
const formDecoded = (value: string): string =>
  new URLSearchParams(`v=${value.replace(/&/g, '%26')}`).get('v') ?? value;

/** `%XX` for one byte, either case of each hex digit. */
const escapePattern = (byte: number): string =>
  `%${[...byte.toString(16).toUpperCase().padStart(2, '0')]
    .map((digit) =>
      /[A-F]/.test(digit) ? `[${digit}${digit.toLowerCase()}]` : digit,
    )
    .join('')}`;

/**
 * One character in every form a server may echo it: as itself, or
 * percent-escaped in any case (`%2F`, `%2f`, `%41` for `A` — a server may
 * escape any character, unreserved ones included); a space also as `+`. So
 * one pattern matches the value as sent, form-encoded,
 * `encodeURIComponent`'d, escaped whole, and any mix of those.
 */
function characterPattern(character: string): string {
  const literal = escapeRegExp(character);
  const escaped = [...Buffer.from(character, 'utf8')]
    .map(escapePattern)
    .join('');
  const space = character === ' ' ? '|\\+' : '';
  return `(?:${literal}|${escaped}${space})`;
}

/**
 * Every value a server may echo a secret as: the secret itself and its
 * form-decoding — what a server decoding a raw `Basic` secret read (UAA,
 * Keycloak), and the original of a `'form'`-encoded one — each matched in any
 * escaping (`characterPattern`).
 */
function echoedValues(secret: string): string[] {
  return [secret, formDecoded(secret)];
}

/**
 * What a reader of the `authDebug` line sees in place of a secret (spec §6,
 * "The preview"): for a form of N characters (code points, so an astral
 * character is never cut), N < 16 → `<redacted, N chars>`; N ≥ 16 → its
 * first 4 and last 4 characters around the marker,
 * `abcd…wxyz <redacted, N chars>` — never more than 8 characters of a form.
 */
export function previewSecret(form: string): string {
  const characters = [...form];
  const length = characters.length;
  const marker = `<redacted, ${length} chars>`;
  if (length < PREVIEW_MIN) return marker;
  const head = characters.slice(0, PREVIEW_EDGE).join('');
  const tail = characters.slice(-PREVIEW_EDGE).join('');
  return `${head}…${tail} ${marker}`;
}

/** Below this many characters a form is shown by its length only. */
const PREVIEW_MIN = 16;
/** How many characters of each end of a form a preview shows. */
const PREVIEW_EDGE = 4;

/**
 * A text cut into what is still the server's (`text`) and what replaced a
 * recognised secret (`preview`): a preview is never scanned again by a later
 * pass, so a short secret inside its marker words is never redacted there.
 */
type Segment = { readonly text: string } | { readonly preview: string };

const joinSegments = (segments: readonly Segment[]): string =>
  segments.map((s) => ('text' in s ? s.text : s.preview)).join('');

/**
 * Applies a pass to the server's text only, leaving every preview as it is.
 * Adjacent text is joined first: a pass must see the server's text between
 * two previews whole — a JWT the base64 pass left in pieces is still one.
 */
function onText(
  segments: readonly Segment[],
  pass: (text: string) => Segment[],
): Segment[] {
  const joined: Segment[] = [];
  for (const segment of segments) {
    const last = joined[joined.length - 1];
    if ('text' in segment && last !== undefined && 'text' in last) {
      joined[joined.length - 1] = { text: last.text + segment.text };
    } else {
      joined.push(segment);
    }
  }
  return joined.flatMap((s) => ('text' in s ? pass(s.text) : [s]));
}

/** Whitespace a server may break a value with, as itself or escaped. */
const WHITESPACE = '[ \\t\\r\\n]|%(?:20|09|0[AaDd])';

/** A value made only of base64 characters (either alphabet), any padding. */
const BASE64_VALUE = /^[A-Za-z0-9+/_-]+={0,2}$/;

/** The value a base64 run stands for once its whitespace and escapes are gone. */
const canonicalBase64 = (value: string): string =>
  value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');

/** Every recognised value of the secrets, and how to find them. */
interface KnownForms {
  /** Every value, longest first; group `i + 1` of `pattern` is `values[i]`. */
  readonly values: readonly string[];
  /** The alternation, one capturing group per value. */
  readonly pattern: string;
  /** A base64 value by its canonical form: a run that is exactly one. */
  readonly base64: ReadonlyMap<string, string>;
}

function knownForms(secrets: readonly (string | undefined)[]): KnownForms {
  // Every value of every secret, longest first: a short one (a password, a
  // decoded secret) redacted inside a longer one (an assertion, the secret as
  // sent) would leave the rest of the longer one unrecognisable.
  const values = [
    ...new Set(
      secrets
        .filter((secret): secret is string => !!secret)
        .flatMap(echoedValues)
        .filter((value) => value !== ''),
    ),
  ].sort((a, b) => b.length - a.length);
  const base64 = new Map<string, string>();
  for (const value of values) {
    if (!BASE64_VALUE.test(value)) continue;
    const canonical = canonicalBase64(value);
    if (!base64.has(canonical)) base64.set(canonical, value);
  }
  return {
    values,
    pattern: values
      .map((value) => `(${[...value].map(characterPattern).join('')})`)
      .join('|'),
    base64,
  };
}

/** The value whose group matched: the form the match was recognised as. */
function matchedForm(
  match: RegExpMatchArray,
  values: readonly string[],
): string {
  for (let i = 0; i < values.length; i++) {
    if (match[i + 1] !== undefined) return values[i] ?? match[0];
  }
  return match[0];
}

/**
 * Replaces every secret the request itself sent (a refresh token, an
 * assertion, a client secret), in each form it may come back in — and then
 * every base64 run of the text (either alphabet, any padding, escaped or not,
 * wrapped or not) that decodes to text holding one (`redactEncodedSecrets`) —
 * each by the preview of the form it was recognised as, never of the span's
 * own characters.
 * Every known secret is redacted, however short: nothing guarantees a client
 * secret is long, and dropping a matching word from a diagnosis is the lesser
 * harm.
 */
function redactKnownSecrets(
  text: string,
  secrets: readonly (string | undefined)[],
): Segment[] {
  const forms = knownForms(secrets);
  if (forms.values.length === 0) return [{ text }];
  // One pass over the original text: an alternation tries the longest value
  // first at each position, and a preview it writes is never scanned again —
  // replaced one value after another, a short one (`ed`) would be redacted
  // inside the markers the longer ones left, and the text would grow per value.
  const segments: Segment[] = [];
  let at = 0;
  for (const match of text.matchAll(new RegExp(forms.pattern, 'g'))) {
    if (match.index > at) segments.push({ text: text.slice(at, match.index) });
    segments.push({ preview: previewSecret(matchedForm(match, forms.values)) });
    at = match.index + match[0].length;
  }
  if (at < text.length) segments.push({ text: text.slice(at) });
  return onText(segments, (piece) => redactEncodedPiece(piece, forms));
}

/**
 * A run of base64 in any form a server may echo it: either alphabet, any of
 * its characters percent-escaped in any case, any padding, and broken by
 * whitespace — a space (a form-decoded `+`), a tab, a line break (a server
 * wrapping lines) — as itself or escaped (`%20`, `%09`, `%0A`, `%0D`).
 */
const BASE64_ESCAPE =
  '%(?:3[0-9]|4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|2[BbDdFf]|5[Ff])';
const BASE64_RUN = new RegExp(
  `(?:[A-Za-z0-9+/_-]|${BASE64_ESCAPE}|${WHITESPACE})+(?:=|%3[Dd]){0,2}`,
  'g',
);
/** Whitespace inside a run: where it is cut into pieces. */
const BREAK = new RegExp(`(?:${WHITESPACE})+`, 'g');
/** Whitespace around a run: the text's, not the run's. */
const AROUND = new RegExp(
  `^((?:${WHITESPACE})*)([\\s\\S]*?)((?:${WHITESPACE})*)$`,
);
/** Never more pieces than this are tried one span at a time. */
const MAX_PIECES = 32;

/**
 * The run as plain base64 — escapes decoded, `+` and `/`, no padding — read
 * both ways whitespace may have come in: dropped (a wrapped line) and as `+`
 * (a form-decoded one).
 */
function normalized(run: string): string[] {
  const unescaped = canonicalBase64(
    run.replace(/%([0-9A-Fa-f]{2})/g, (_escape, hex: string) =>
      String.fromCharCode(Number.parseInt(hex, 16)),
    ),
  );
  return [
    unescaped.replace(/[ \t\r\n]/g, ''),
    unescaped.replace(/[\t\r\n]/g, '').replace(/ /g, '+'),
  ];
}

/**
 * The form a run was recognised as, else undefined: the base64 value it is,
 * whitespace and escapes stripped (the plain Basic credential); else the
 * secret its decoding, from any of its four alignments, holds.
 */
function recognisedForm(run: string, forms: KnownForms): string | undefined {
  const plains = normalized(run);
  for (const plain of plains) {
    const value = forms.base64.get(plain);
    if (value !== undefined) return value;
  }
  const secret = new RegExp(forms.pattern);
  for (const plain of plains) {
    for (let offset = 0; offset < 4 && offset < plain.length; offset++) {
      const decoded = Buffer.from(plain.slice(offset), 'base64').toString(
        'utf8',
      );
      const match = secret.exec(decoded);
      if (match) return matchedForm(match, forms.values);
    }
  }
  return undefined;
}

/**
 * Replaces, within a run split at its whitespace into pieces, first a span of
 * whole pieces that is itself a known base64 value — a Basic credential,
 * wrapped, unpadded or URL-safe, replaced whole and never piece by piece
 * (spec §6, "Recognition first") — else the smallest span that still holds
 * a secret once decoded; then looks again on either side of it: a run may be
 * a sentence around one credential.
 */
function redactRun(run: string, forms: KnownForms): Segment[] {
  const form = recognisedForm(run, forms);
  if (form === undefined) return [{ text: run }];
  const whole: Segment[] = [{ preview: previewSecret(form) }];
  const pieces: { start: number; end: number }[] = [];
  let start = 0;
  for (const space of run.matchAll(BREAK)) {
    if (space.index > start) pieces.push({ start, end: space.index });
    start = space.index + space[0].length;
  }
  if (start < run.length) pieces.push({ start, end: run.length });
  if (pieces.length <= 1 || pieces.length > MAX_PIECES) return whole;
  const around = (from: number, to: number, found: string): Segment[] => [
    ...redactRun(run.slice(0, from), forms),
    { preview: previewSecret(found) },
    ...redactRun(run.slice(to), forms),
  ];
  const spans = function* (): Generator<[number, number]> {
    for (let size = 1; size <= pieces.length; size++) {
      for (let first = 0; first + size <= pieces.length; first++) {
        yield [
          pieces[first]?.start ?? 0,
          pieces[first + size - 1]?.end ?? run.length,
        ];
      }
    }
  };
  for (const [from, to] of spans()) {
    for (const plain of normalized(run.slice(from, to))) {
      const value = forms.base64.get(plain);
      if (value !== undefined) return around(from, to, value);
    }
  }
  for (const [from, to] of spans()) {
    const found = recognisedForm(run.slice(from, to), forms);
    if (found !== undefined) return around(from, to, found);
  }
  return whole;
}

/**
 * Every base64 run of the server's text that decodes to text holding a
 * secret: a server may echo a Basic credential, or base64-encode a secret, in
 * any equivalent form — without padding, with other padding, URL-safe,
 * escaped, wrapped — which no fixed list of forms can enumerate. What is
 * decoded is matched by the same pattern as the text itself. Called on the
 * text between previews only: a preview is never scanned again.
 */
function redactEncodedPiece(text: string, forms: KnownForms): Segment[] {
  const segments: Segment[] = [];
  let at = 0;
  for (const match of text.matchAll(BASE64_RUN)) {
    const run = match[0];
    const [, before = '', core = '', after = ''] = AROUND.exec(run) ?? [];
    if (core.length < 2) continue;
    segments.push({ text: text.slice(at, match.index) + before });
    segments.push(...redactRun(core, forms));
    segments.push({ text: after });
    at = match.index + run.length;
  }
  segments.push({ text: text.slice(at) });
  return segments;
}

const escapeRegExp = (value: string): string =>
  value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * The registered OAuth error codes a token endpoint (or the device
 * authorization endpoint) answers with: RFC 6749 §5.2 and §4.1.2.1, RFC 8628
 * §3.5, RFC 6750 §3.1, RFC 8693 §2.2.2. Each is a fixed protocol word, never
 * a secret, and control flow reads it (the device poll continues on
 * `authorization_pending` and `slow_down`): an `error` exactly equal to one is
 * kept verbatim, because redacting a secret that happens to be a substring
 * (`a` in `authorization_pending`) would rewrite the code itself. Any other
 * `error` value is redacted like every other field.
 */
const REGISTERED_ERROR_CODES: ReadonlySet<string> = new Set([
  // RFC 6749 §5.2 — token endpoint
  'invalid_request',
  'invalid_client',
  'invalid_grant',
  'unauthorized_client',
  'unsupported_grant_type',
  'invalid_scope',
  // RFC 6749 §4.1.2.1 — authorization endpoint, also seen from token endpoints
  'access_denied',
  'unsupported_response_type',
  'server_error',
  'temporarily_unavailable',
  // RFC 8628 §3.5 — device access token response
  'authorization_pending',
  'slow_down',
  'expired_token',
  // RFC 6750 §3.1 — bearer token usage
  'invalid_token',
  'insufficient_scope',
  // RFC 8693 §2.2.2 — token exchange
  'invalid_target',
  // OpenID Connect Core 1.0 §3.1.2.6 — authentication error response
  'interaction_required',
  'login_required',
  'account_selection_required',
  'consent_required',
  'invalid_request_uri',
  'invalid_request_object',
  'request_not_supported',
  'request_uri_not_supported',
  'registration_not_supported',
]);

/** The value when it is a registered OAuth / OIDC error code, else undefined. */
export function registeredOAuthError(value: unknown): string | undefined {
  return typeof value === 'string' && REGISTERED_ERROR_CODES.has(value)
    ? value
    : undefined;
}

/** `error` as it may stay: a registered code verbatim, anything else redacted. */
function errorCode(
  value: string,
  secrets: readonly (string | undefined)[],
): string {
  return REGISTERED_ERROR_CODES.has(value) ? value : redact(value, secrets);
}

/**
 * Previews what a server might echo back: every known secret, and any JWT —
 * the JWT pass, like the base64 one, reads the server's text between the
 * previews only.
 */
function redact(
  text: string,
  secrets: readonly (string | undefined)[],
): string {
  return joinSegments(
    onText(redactKnownSecrets(text, secrets), (piece) => {
      const segments: Segment[] = [];
      let at = 0;
      for (const match of piece.matchAll(JWT_SHAPE)) {
        segments.push({ text: piece.slice(at, match.index) });
        segments.push({ preview: previewSecret(match[0]) });
        at = match.index + match[0].length;
      }
      segments.push({ text: piece.slice(at) });
      return segments;
    }),
  );
}

/**
 * @param knownSecrets what the request sent that must never come back out:
 *   the refresh token, the assertion, the client secret.
 */
export function describeOAuthErrorBody(
  data: unknown,
  knownSecrets: readonly (string | undefined)[] = [],
): string {
  if (!data || typeof data !== 'object') return 'no error given';
  const { error, error_description } = data as {
    error?: unknown;
    error_description?: unknown;
  };
  const parts: string[] = [];
  if (typeof error === 'string')
    parts.push(quote(errorCode(error, knownSecrets), ERROR_CAP));
  if (typeof error_description === 'string') {
    parts.push(quote(redact(error_description, knownSecrets), DESCRIPTION_CAP));
  }
  return parts.length > 0 ? parts.join(': ') : 'no error given';
}

/** RFC 6749 §5.2's fields of an error response, the only ones kept. */
export interface OAuthErrorFields {
  error?: string;
  error_description?: string;
  error_uri?: string;
}

/**
 * An error body reduced to `error`, `error_description` and `error_uri` (each
 * only when a string), every known secret and any JWT redacted — except an
 * `error` that is a registered code, kept verbatim — what may stay
 * on a thrown error. Anything else a server put in the body (a token, an echo
 * of the request) is dropped; a body that is not an object becomes undefined.
 */
export function oauthErrorFields(
  data: unknown,
  knownSecrets: readonly (string | undefined)[] = [],
): OAuthErrorFields | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const out: OAuthErrorFields = {};
  for (const field of ['error', 'error_description', 'error_uri'] as const) {
    const value = (data as Record<string, unknown>)[field];
    if (typeof value !== 'string') continue;
    out[field] =
      field === 'error'
        ? errorCode(value, knownSecrets)
        : redact(value, knownSecrets);
  }
  return out;
}
