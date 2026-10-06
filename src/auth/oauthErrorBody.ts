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

/**
 * A token a JWT may be found in: base64url characters and dots, maximal.
 * Linear: one character class, nothing to backtrack into.
 */
const JWT_TOKEN = /[A-Za-z0-9_.-]+/g;

/**
 * Every JWT-shaped span of a token — `eyJ…` and at least one character,
 * a dot, a second non-empty segment, a dot, a third segment (5.4.2's
 * `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`, leftmost first) —
 * found segment by segment, so each character is read a fixed number of
 * times: the regex retried at every `eyJ` of `eyJeyJeyJ…` was quadratic.
 */
function jwtSpans(token: string): [start: number, end: number][] {
  const segments: { start: number; end: number }[] = [];
  let start = 0;
  for (;;) {
    const dot = token.indexOf('.', start);
    segments.push({ start, end: dot < 0 ? token.length : dot });
    if (dot < 0) break;
    start = dot + 1;
  }
  // Every `eyJ`, found once, read in order: no search runs past its segment.
  const heads: number[] = [];
  for (
    let at = token.indexOf('eyJ');
    at >= 0;
    at = token.indexOf('eyJ', at + 1)
  ) {
    heads.push(at);
  }
  const spans: [number, number][] = [];
  let next = 0;
  for (let k = 0; k + 2 < segments.length; k++) {
    const head = segments[k];
    const body = segments[k + 1];
    const tail = segments[k + 2];
    if (!head || !body || !tail) break;
    while ((heads[next] ?? Number.POSITIVE_INFINITY) < head.start) next++;
    const at = heads[next];
    if (at === undefined || at + 3 >= head.end || body.end === body.start) {
      continue;
    }
    spans.push([at, tail.end]);
    k += 2;
  }
  return spans;
}

/**
 * A value as a server reading it `application/x-www-form-urlencoded` decodes
 * it (RFC 6749 §2.3.1): `+` a space, `%XX` its byte, the whole value — `&`
 * and `=` are part of it, never a separator. Never throws: a malformed escape
 * stays as it is (WHATWG percent-decoding).
 */
const formDecoded = (value: string): string =>
  new URLSearchParams(`v=${value.replace(/&/g, '%26')}`).get('v') ?? value;

/**
 * The `%` of an escape at any depth: a server escaping its echo again turns
 * `%2B` into `%252B`, then `%25252B` — the `%` escaped as `%25` each time.
 * Unbounded on purpose: `(?:25)*` is linear to match, so no depth escapes
 * recognition, and no bound needs a reason.
 */
const ESCAPE = '%(?:25)*';

/** `%XX` for one byte at any escaping depth, either case of each hex digit. */
const escapePattern = (byte: number): string =>
  `${ESCAPE}${[...byte.toString(16).toUpperCase().padStart(2, '0')]
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
  // A space form-encoded is `+`, and that `+` escaped again `%2B`.
  const space = character === ' ' ? `|\\+|${ESCAPE}2[Bb]` : '';
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
const WHITESPACE = `[ \\t\\r\\n]|${ESCAPE}(?:20|09|0[AaDd])`;

/** A value made only of base64 characters (either alphabet), any padding. */
const BASE64_VALUE = /^[A-Za-z0-9+/_-]+={0,2}$/;

/** The value a base64 run stands for once its whitespace and escapes are gone. */
const canonicalBase64 = (value: string): string => {
  const plain = value.replace(/-/g, '+').replace(/_/g, '/');
  // Trailing `=` cut by a scan: `/=+$/` retried at every `=` is quadratic.
  let end = plain.length;
  while (end > 0 && plain[end - 1] === '=') end--;
  return plain.slice(0, end);
};

/** One escape at any depth (`%2B`, `%252B`, `%25252B`), its byte captured. */
const ANY_DEPTH_ESCAPE = /%(?:25)*([0-9A-Fa-f]{2})/g;
/** A run of such escapes, decoded together (a UTF-8 character spans bytes). */
const ESCAPE_RUN = /(?:%(?:25)*[0-9A-Fa-f]{2})+/g;

/**
 * A text with every percent-escape decoded, whatever its depth: `%(?:25)*XX`
 * is one step to its byte, so a chain `%2525…2541` costs its length once,
 * never once per level. Repeated until nothing changes, for an escape built
 * from escaped characters (`%%32B` → `%2B` → `+`): each such level costs a
 * text about three times longer, so the rounds grow with the logarithm of
 * the length, and each round that changes anything shortens the text. The
 * escaped bytes are read as Latin-1 (the base64 pass: one character per
 * byte) or as UTF-8 (the fail-closed net: a secret's own characters).
 */
/** A run of escapes as text: ASCII bytes directly, anything else through a Buffer. */
function decodedRun(run: string, bytesAs: 'latin1' | 'utf8'): string {
  let ascii = '';
  for (const found of run.matchAll(ANY_DEPTH_ESCAPE)) {
    const byte = Number.parseInt(found[1] ?? '', 16);
    if (byte >= 0x80) {
      return Buffer.from(
        run.replace(ANY_DEPTH_ESCAPE, (_escape, hex: string) => hex),
        'hex',
      ).toString(bytesAs);
    }
    ascii += String.fromCharCode(byte);
  }
  return ascii;
}

function unescapedFully(
  text: string,
  bytesAs: 'latin1' | 'utf8' = 'latin1',
): string {
  let current = text;
  for (;;) {
    const next = current.replace(ESCAPE_RUN, (run) => decodedRun(run, bytesAs));
    if (next === current) return current;
    current = next;
  }
}

/**
 * The pattern of one value: each character in every escaped form, and —
 * for a value with no whitespace of its own — any wrapping whitespace (raw,
 * or escaped at any depth) between two characters, so a secret a server
 * line-wrapped is recognised whole, as one span, before any shape pass can
 * take a piece of it. A value holding whitespace gets none: its own spaces
 * and a wrap could not be told apart, and the ambiguity would backtrack.
 */
function valuePattern(value: string): string {
  const characters = [...value].map(characterPattern);
  return /[ \t\r\n]/.test(value)
    ? characters.join('')
    : characters.join(`(?:${WHITESPACE})*`);
}

/** Every recognised value of the secrets, and how to find them. */
interface KnownForms {
  /** Every value, longest first; group `i + 1` of `pattern` is `values[i]`. */
  readonly values: readonly string[];
  /** The alternation, one capturing group per value. */
  readonly pattern: string;
  /** A base64 value by its canonical form: a run that is exactly one. */
  readonly base64: ReadonlyMap<string, string>;
  /** The length of the shortest value: a decoding shorter than it holds none. */
  readonly shortest: number;
  /**
   * The shortest run that can matter: a known base64 value's length, or the
   * base64 length whose decoding can reach the shortest value (⌈4c/3⌉).
   */
  readonly shortestRun: number;
  /** `pattern` compiled once, not global: what a decoded reading is tested with. */
  readonly secret: RegExp;
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
  const pattern = values.map((value) => `(${valuePattern(value)})`).join('|');
  const shortest = Math.min(...values.map((value) => value.length));
  const shortestRun = Math.min(
    Math.ceil((shortest * 4) / 3),
    ...[...base64.keys()].map((value) => value.length),
  );
  return {
    values,
    pattern,
    base64,
    shortest,
    shortestRun,
    secret: new RegExp(pattern),
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
function redactKnownSecrets(text: string, forms: KnownForms): Segment[] {
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
  return segments;
}

/**
 * A run of base64 in any form a server may echo it: either alphabet, any of
 * its characters percent-escaped in any case, any padding, and broken by
 * whitespace — a space (a form-decoded `+`), a tab, a line break (a server
 * wrapping lines) — as itself or escaped (`%20`, `%09`, `%0A`, `%0D`).
 */
const BASE64_ESCAPE = `${ESCAPE}(?:3[0-9]|4[1-9A-Fa-f]|5[0-9Aa]|6[1-9A-Fa-f]|7[0-9Aa]|2[BbDdFf]|5[Ff])`;
const BASE64_RUN = new RegExp(
  `(?:[A-Za-z0-9+/_-]|${BASE64_ESCAPE}|${WHITESPACE})+(?:=|${ESCAPE}3[Dd]){0,2}`,
  'g',
);
/** Whitespace inside a run: where it is cut into pieces. */
const BREAK = new RegExp(`(?:${WHITESPACE})+`, 'g');
/** Whitespace at the start of a run (sticky: matched at index 0 only). */
const LEADING = new RegExp(`(?:${WHITESPACE})+`, 'y');

/**
 * A run cut into the whitespace around it — the text's, not the run's — and
 * its core. Anchored trims instead of 5.4.2's `^(ws*)([\s\S]*?)(ws*)$`,
 * whose lazy middle retried the trailing group at every character of a long
 * whitespace run (quadratic): the leading run is one sticky match, the
 * trailing one the last `BREAK` match that ends the run.
 */
function around(run: string): [before: string, core: string, after: string] {
  LEADING.lastIndex = 0;
  const lead = LEADING.exec(run)?.[0].length ?? 0;
  if (lead === run.length) return [run, '', ''];
  let tail = run.length;
  for (const space of run.matchAll(BREAK)) {
    if (space.index >= lead && space.index + space[0].length === run.length) {
      tail = space.index;
    }
  }
  return [run.slice(0, lead), run.slice(lead, tail), run.slice(tail)];
}
/** Never more pieces than this are tried one span at a time. */
const MAX_PIECES = 32;

/**
 * The run as plain base64 — escapes decoded, `+` and `/`, no padding — read
 * both ways whitespace may have come in: dropped (a wrapped line) and as `+`
 * (a form-decoded one).
 */
function normalized(run: string): string[] {
  const unescaped = canonicalBase64(unescapedFully(run));
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
  const secret = forms.secret;
  for (const plain of plains) {
    // Too short to decode to the shortest value: nothing to decode (a value
    // of c characters needs at least c bytes, and L base64 characters
    // decode to at most ⌊3L/4⌋).
    if (Math.floor((plain.length * 3) / 4) < forms.shortest) continue;
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
    const [before, core, after] = around(run);
    // Too short to be a known base64 value or to decode to the shortest
    // value (escapes only shorten a run): left as it is, undecoded.
    if (core.length < 2 || core.length < forms.shortestRun) continue;
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
 * The fail-closed net, last: a piece of the server's text that, decoded at
 * every depth, still holds a known secret in some way the passes above did
 * not recognise (an escaping no pattern foresaw) is replaced whole by its
 * length alone — over-redaction, never a secret.
 */
function failClosed(piece: string, forms: KnownForms): Segment[] {
  if (forms.values.length === 0) return [{ text: piece }];
  const secret = forms.secret;
  // A server may also wrap a secret that is not base64 — a line break, a
  // space or a tab inside it, raw or escaped at any depth, even inside an
  // escape it split: every reading is tried with all of it removed too,
  // before decoding and after.
  const unwrapped = piece.replace(WRAPPING, '');
  const readings = [...new Set([piece, unwrapped])].flatMap((text) =>
    (text.includes('%')
      ? [text, unescapedFully(text, 'utf8'), unescapedFully(text)]
      : [text]
    ).flatMap((reading) => [reading, reading.replace(/[ \t\r\n]+/g, '')]),
  );
  return readings.some((reading) => secret.test(reading))
    ? [{ preview: `<redacted, ${[...piece].length} chars>` }]
    : [{ text: piece }];
}

/** Whitespace a server wraps with, raw or escaped at any depth. */
const WRAPPING = new RegExp(`(?:${WHITESPACE})+`, 'g');

/** The JWT pass: anything JWT-shaped in the server's text, previewed. */
function previewJwts(piece: string): Segment[] {
  const segments: Segment[] = [];
  let at = 0;
  for (const token of piece.matchAll(JWT_TOKEN)) {
    for (const [start, end] of jwtSpans(token[0])) {
      segments.push({ text: piece.slice(at, token.index + start) });
      segments.push({
        preview: previewSecret(token[0].slice(start, end)),
      });
      at = token.index + end;
    }
  }
  segments.push({ text: piece.slice(at) });
  return segments;
}

/**
 * At most `cap` characters (code points) of a redacted text, then `…`: the
 * server's text is cut at a character, never inside a surrogate pair, and a
 * preview is kept whole or left out whole, never cut — after redaction, so
 * no cut can split a secret before it was recognised.
 */
function capped(segments: readonly Segment[], cap: number): string {
  let out = '';
  let left = cap;
  for (const segment of segments) {
    const characters = [
      ...('text' in segment ? segment.text : segment.preview),
    ];
    if (characters.length <= left) {
      out += characters.join('');
      left -= characters.length;
      continue;
    }
    if ('text' in segment) out += characters.slice(0, left).join('');
    return `${out}…`;
  }
  return out;
}

/**
 * Previews what a server might echo back: every known secret, at any depth
 * of escaping, and any JWT — each pass reading the server's text between the
 * previews only — then the fail-closed net, then the cap (5.4.2's 512).
 */
function redact(
  text: string,
  secrets: readonly (string | undefined)[],
): string {
  const forms = knownForms(secrets);
  // Every check against a KNOWN secret first — its forms, escaped and
  // wrapped (one span each), then the fail-closed net — and only then the
  // shape passes (base64 runs, JWT-shaped): a shape pass never takes a
  // fragment of a known secret before it was recognised whole.
  const known = onText(redactKnownSecrets(text, forms), (piece) =>
    failClosed(piece, forms),
  );
  const segments = onText(
    onText(known, (piece) => redactEncodedPiece(piece, forms)),
    previewJwts,
  );
  return capped(segments, DESCRIPTION_CAP);
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
