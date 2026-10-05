/**
 * What of an OAuth error response may reach a log line or an error message.
 *
 * Only RFC 6749 §5.2's `error` and `error_description`, each quoted and capped.
 * A token endpoint's body is otherwise untrusted: a misbehaving server can echo
 * the request or return tokens in it, so it is never serialised whole.
 * `error_description` is the server's human-readable diagnosis, so it keeps a
 * cap long enough to stay useful (UAA explains assertion refusals in it).
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

/** Characters RFC 3986 never escapes: matched only as themselves. */
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

/** `%XX` for one byte, either case of each hex digit. */
const escapePattern = (byte: number): string =>
  `%${[...byte.toString(16).toUpperCase().padStart(2, '0')]
    .map((digit) =>
      /[A-F]/.test(digit) ? `[${digit}${digit.toLowerCase()}]` : digit,
    )
    .join('')}`;

/**
 * One character in every form a server may echo it: as itself, or
 * percent-escaped in any case (`%2F`, `%2f`); a space also as `+`. So one
 * pattern matches the value as sent, form-encoded, `encodeURIComponent`'d,
 * and any mix of those.
 */
function characterPattern(character: string): string {
  const literal = escapeRegExp(character);
  if (UNRESERVED.test(character)) return literal;
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
 * Replaces every secret the request itself sent (a refresh token, an
 * assertion, a client secret), in each form it may come back in — and then
 * every base64 run of the text (either alphabet, any padding, escaped or not)
 * that decodes to text holding one (`redactEncodedSecrets`).
 * Every known secret is redacted, however short: nothing guarantees a client
 * secret is long, and dropping a matching word from a diagnosis is the lesser
 * harm.
 */
function redactKnownSecrets(
  text: string,
  secrets: readonly (string | undefined)[],
): string {
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
  if (values.length === 0) return text;
  const pattern = values
    .map((value) => [...value].map(characterPattern).join(''))
    .join('|');
  // One pass over the original text: an alternation tries the longest value
  // first at each position, and a marker it writes is never scanned again —
  // replaced one value after another, a short one (`ed`) would be redacted
  // inside the markers the longer ones left, and the text would grow per value.
  const redacted = text.replace(new RegExp(pattern, 'g'), REDACTED);
  return redactEncodedSecrets(redacted, new RegExp(pattern));
}

const REDACTED = '<redacted>';

/**
 * A run of base64 in any form a server may echo it: either alphabet, `+` `/`
 * and `=` escaped in any case, a `+` read as a space (`%20` or ` `), any
 * padding.
 */
const BASE64_RUN = /(?:[A-Za-z0-9+/_-]|%2[BbFf]|%20| )+(?:=|%3[Dd]){0,2}/g;
/** Separators a form-decoded `+` became: a run is shrunk at these. */
const SPACE = /%20| /g;
/** Never more pieces than this are tried one span at a time. */
const MAX_PIECES = 32;

/** The run as plain base64: `+` and `/`, no escapes, no padding. */
const normalized = (run: string): string =>
  run
    .replace(/%2[Bb]|%20| |-/g, '+')
    .replace(/%2[Ff]|_/g, '/')
    .replace(/(?:=|%3[Dd])+$/, '');

/** True when the run, decoded from any of its four alignments, holds a secret. */
function holdsSecret(run: string, secret: RegExp): boolean {
  const plain = normalized(run);
  for (let offset = 0; offset < 4 && offset < plain.length; offset++) {
    const decoded = Buffer.from(plain.slice(offset), 'base64').toString('utf8');
    if (secret.test(decoded)) return true;
  }
  return false;
}

/**
 * Redacts the smallest span of whole pieces (a run split at its spaces) that
 * still holds a secret, then looks again on either side of it: a run may be
 * a sentence around one credential.
 */
function redactRun(run: string, secret: RegExp): string {
  if (!holdsSecret(run, secret)) return run;
  const pieces: { start: number; end: number }[] = [];
  let start = 0;
  for (const space of run.matchAll(SPACE)) {
    if (space.index > start) pieces.push({ start, end: space.index });
    start = space.index + space[0].length;
  }
  if (start < run.length) pieces.push({ start, end: run.length });
  if (pieces.length <= 1 || pieces.length > MAX_PIECES) return REDACTED;
  for (let size = 1; size <= pieces.length; size++) {
    for (let first = 0; first + size <= pieces.length; first++) {
      const from = pieces[first]?.start ?? 0;
      const to = pieces[first + size - 1]?.end ?? run.length;
      if (holdsSecret(run.slice(from, to), secret)) {
        return `${redactRun(run.slice(0, from), secret)}${REDACTED}${redactRun(run.slice(to), secret)}`;
      }
    }
  }
  return REDACTED;
}

/**
 * Every base64 run of the text that decodes to text holding a secret: a
 * server may echo a Basic credential, or base64-encode a secret, in any
 * equivalent form — without padding, with other padding, URL-safe, escaped —
 * which no fixed list of forms can enumerate. What is decoded is matched by
 * the same pattern as the text itself.
 */
function redactEncodedSecrets(text: string, secret: RegExp): string {
  // Between the markers only: a marker is never scanned again.
  return text
    .split(REDACTED)
    .map((piece) => redactEncodedPiece(piece, secret))
    .join(REDACTED);
}

function redactEncodedPiece(text: string, secret: RegExp): string {
  return text.replace(BASE64_RUN, (run) => {
    // The spaces around a run are the text's, not the run's.
    const [, before = '', core = '', after = ''] =
      /^((?:%20| )*)(.*?)((?:%20| )*)$/s.exec(run) ?? [];
    return core.length < 2
      ? run
      : `${before}${redactRun(core, secret)}${after}`;
  });
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

/** Removes what a server might echo back: every known secret, and any JWT. */
function redact(
  text: string,
  secrets: readonly (string | undefined)[],
): string {
  return redactKnownSecrets(text, secrets).replace(JWT_SHAPE, '<redacted jwt>');
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
