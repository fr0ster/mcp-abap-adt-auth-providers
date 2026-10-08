/**
 * What a token says about its binding to a client certificate (RFC 8705 §3.1).
 * Read before the token is presented; nothing is verified — the token's
 * signature is the resource's to check, not the client's.
 */

/**
 * - `bound` — a JWT whose payload carries `cnf`. `thumbprint` is its
 *   `cnf["x5t#S256"]`, or undefined when `cnf` is there but is not an object
 *   with a non-empty string `x5t#S256` (null, a string, an array, a `jkt`
 *   binding, an empty value): bound to something, so never treated as
 *   unbound — and undefined equals no pinned thumbprint, so the provider
 *   answers the row "bound — none, or another thumbprint" (fail closed).
 * - `unbound` — a JWT whose payload has no `cnf` property.
 * - `unknown` — anything else: an opaque token, cookies, a JWT that does not
 *   parse. Its binding, if any, lives on the server (RFC 8705 §3.2).
 */
export type TokenBinding =
  | { state: 'bound'; thumbprint: string | undefined }
  | { state: 'unbound' }
  | { state: 'unknown' };

/** Header and payload non-empty; the signature may be empty (`alg: none`). */
const JWT_SHAPE = /^[A-Za-z0-9_-]+\.([A-Za-z0-9_-]+)\.[A-Za-z0-9_-]*$/;

export function readBinding(token: string): TokenBinding {
  const encoded = JWT_SHAPE.exec(token)?.[1];
  if (encoded === undefined) return { state: 'unknown' };
  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    return { state: 'unknown' };
  }
  if (
    payload === null ||
    typeof payload !== 'object' ||
    Array.isArray(payload)
  ) {
    return { state: 'unknown' };
  }
  if (!Object.hasOwn(payload, 'cnf')) return { state: 'unbound' };
  const cnf = (payload as { cnf: unknown }).cnf;
  const thumbprint =
    cnf !== null && typeof cnf === 'object' && !Array.isArray(cnf)
      ? (cnf as Record<string, unknown>)['x5t#S256']
      : undefined;
  return {
    state: 'bound',
    thumbprint:
      typeof thumbprint === 'string' && thumbprint.length > 0
        ? thumbprint
        : undefined,
  };
}
