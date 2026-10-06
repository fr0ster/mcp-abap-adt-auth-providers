/**
 * One token request authenticated by an `IClientAuthentication` (spec §3).
 *
 * The request is the grant's own parameters, plus what `authenticate(draft)`
 * returned: its parameters added to the body, its headers to the request, its
 * `endpoint`, when it names one, in place of the URL. Pinned TLS material
 * becomes an `https.Agent` carrying exactly that material — server
 * verification is left as Node does it: `rejectUnauthorized` is never set, and
 * a private CA is `NODE_EXTRA_CA_CERTS`.
 *
 * Pinned material past its `notAfter` is refused first, before every request
 * (a `CertificateMaterialError`, "has expired"). What the strategy returned is
 * checked before anything is sent: a value that
 * is not a string, a header with a line break, a parameter or header that
 * would replace one of the site's own, an endpoint that is not an absolute `https:` URL —
 * each throws a `ClientAuthenticationResultError`, whose words are fixed.
 * `http:` is accepted only where the configured endpoint is itself `http:` (a
 * local server, the provider stand's UAA), and never with material, which an
 * `http:` request would silently not present.
 *
 * Without a strategy no site comes here: each keeps its own private adapter,
 * which sends exactly what that site sent before strategies existed — except
 * that no request on either path follows a redirect (`maxRedirects: 0`).
 */

import { Agent } from 'node:https';
import {
  AuthProviderFailure,
  authError,
  httpStatus,
  isOAuthErrorCode,
  isSystemCode,
  render,
} from '@mcp-abap-adt/auth-errors';
import type {
  ICertificateMaterial,
  IClientAuthentication,
  ITokenRequestAuthentication,
  ITokenRequestDraft,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, {
  AxiosError,
  type AxiosRequestConfig,
  type AxiosResponse,
  CanceledError,
} from 'axios';
import { ClientAuthenticationResultError } from '../errors/ClientAuthenticationError';
import { TokenEndpointError } from '../errors/TokenEndpointError';
import { assertNotExpired } from './certificateMaterial';
import type { OAuth2GrantType, Operation } from './contractTransition';
import {
  allowlistedCode,
  integerStatus,
  readSafely,
  tlsFailureCode,
} from './knownCodes';
import { type OAuthErrorFields, registeredOAuthError } from './oauthErrorBody';
import { loggedError } from './refusal';

/** What a site is given to authenticate one request with a strategy. */
export interface TokenRequestAuth {
  readonly strategy: IClientAuthentication;
  /** The strategy's TLS material, already pinned by the provider. */
  readonly material?: ICertificateMaterial | undefined;
  /**
   * The pinned certificate's `notAfter` (epoch ms). Checked before every
   * request that presents the material — a device poll may outlive it — so no
   * expired certificate is sent.
   */
  readonly notAfter?: number | undefined;
  /** The server's mTLS alias of this request's endpoint (RFC 8705 §5), when it published one. */
  readonly mtlsEndpoint?: string | undefined;
  /**
   * The authorization server's plain token endpoint (never its mTLS alias),
   * for the device initiation, whose request goes elsewhere. A token request
   * names its own endpoint; this is not read for one.
   */
  readonly tokenEndpoint?: string | undefined;
}

/** One request, before the client is authenticated. */
export interface GrantRequest {
  /** The URL the site sends to without a strategy: the draft's endpoint. */
  readonly endpoint: string;
  readonly clientId: string;
  /** The draft's grant type; `device_authorization` for the device initiation. */
  readonly grantType: string;
  /** The grant's own body parameters. */
  readonly parameters: URLSearchParams;
  /** The site's own headers besides Content-Type (passcode: Accept). */
  readonly headers?: Readonly<Record<string, string>> | undefined;
  readonly timeout?: number | undefined;
}

export interface PreparedTokenRequest {
  /** The whole axios config: url, method, headers, data, and httpsAgent / timeout when set. */
  readonly config: AxiosRequestConfig;
  /**
   * The secrets the strategy put on the request, by name: `client_secret`,
   * `client_assertion`, and a Basic credential (`basic`, `basic_secret`) —
   * what the `authDebug` line names in `sent`, each through `prepareSecret`.
   */
  readonly secrets: SentSecrets;
}

/**
 * The secrets a request carried, by the name it carried them under
 * (`refresh_token`, `client_secret`, `basic`, …). A value is passed to a log
 * line only through `prepareSecret`; nothing ever looks for one in text.
 */
export type SentSecrets = Readonly<Record<string, string | undefined>>;

const FORM = 'application/x-www-form-urlencoded';
/**
 * A strategy's parameters whose values are secrets, named in `sent` with the
 * credential of an `Authorization: Basic` header (`basicSecrets`). A custom
 * strategy's secret in any other parameter or header is not known to be one;
 * it is never logged either way — nothing of a request is logged but `sent`.
 */
const SECRET_PARAMETERS = ['client_secret', 'client_assertion'];

function unusable(): never {
  throw new ClientAuthenticationResultError();
}

function stringRecord(value: unknown): Record<string, string> {
  if (value === undefined) return {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) unusable();
  const out: Record<string, string> = {};
  for (const [name, item] of Object.entries(value)) {
    if (typeof item !== 'string') unusable();
    out[name] = item;
  }
  return out;
}

function targetUrl(
  configured: string,
  named: unknown,
  material: ICertificateMaterial | undefined,
): string {
  if (named === undefined) {
    if (material && !configured.startsWith('https:')) unusable();
    return configured;
  }
  if (typeof named !== 'string') unusable();
  let url: URL;
  try {
    url = new URL(named);
  } catch {
    unusable();
  }
  const local = !material && configured.startsWith('http:');
  if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) {
    unusable();
  }
  return named;
}

/**
 * An agent carrying the four material fields and nothing else: a field the
 * material object happens to carry at run time (`rejectUnauthorized`, `ca`,
 * `checkServerIdentity`) never reaches it.
 */
function agentFor(material: ICertificateMaterial): Agent {
  const { cert, key, pfx, passphrase } = material;
  return new Agent({
    ...(cert === undefined ? {} : { cert }),
    ...(key === undefined ? {} : { key }),
    ...(pfx === undefined ? {} : { pfx }),
    ...(passphrase === undefined ? {} : { passphrase }),
  });
}

/** Whitespace as the regex `\s` reads it: exactly what `trim()` removes. */
const isWhitespace = (character: string): boolean => character.trim() === '';

/**
 * The credential of one `Basic` header value, accepting exactly what 5.4.2's
 * `/^Basic\s+(\S+)$/i` accepted, in plain code: `basic` in any case, at
 * least one whitespace character (`\s`: NBSP, `\v`, `\f` included), then a
 * non-empty token with no whitespace to the very end — trailing whitespace
 * refuses the value, as `$` after `\S+` did.
 */
function basicCredential(value: string): string | undefined {
  if (value.slice(0, 5).toLowerCase() !== 'basic') return undefined;
  const characters = [...value.slice(5)];
  let at = 0;
  while (at < characters.length && isWhitespace(characters[at] ?? '')) at++;
  if (at === 0 || at === characters.length) return undefined;
  const token = characters.slice(at);
  return token.some(isWhitespace) ? undefined : token.join('');
}

/**
 * The secrets of every `Authorization: Basic` header, by name — as 5.4.2
 * read every header named `authorization` in any case: `basic`, the base64
 * credential as sent, and `basic_secret`, the secret after its first colon;
 * a second such header (another casing of the name) `basic_2` /
 * `basic_secret_2`, and so on, so `sent` names each.
 */
function basicSecrets(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  let found = 0;
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() !== 'authorization') continue;
    const credential = basicCredential(value);
    if (credential === undefined) continue;
    found++;
    const suffix = found === 1 ? '' : `_${found}`;
    out[`basic${suffix}`] = credential;
    const decoded = Buffer.from(credential, 'base64').toString();
    const colon = decoded.indexOf(':');
    if (colon >= 0 && colon < decoded.length - 1) {
      out[`basic_secret${suffix}`] = decoded.slice(colon + 1);
    }
  }
  return out;
}

/**
 * A site's own `Authorization: Basic` header on the path without a strategy,
 * with the secrets a server echoing it would hand back.
 */
export interface LegacyBasic {
  /** `Basic ${base64(id:secret)}`. */
  readonly header: string;
  /** What `basicSecrets()` reads of it: `basic` and `basic_secret`. */
  readonly secrets: SentSecrets;
}

/**
 * The one place a site without a strategy builds its Basic header. Its
 * secrets come from the same `basicSecrets()` a strategy's Basic credential
 * goes through: a site passes the result as `TokenRequestSite.basic`, so
 * the `authDebug` line names it in `sent` (spec §6).
 */
export function legacyBasic(
  clientId: string,
  clientSecret: string,
): LegacyBasic {
  const header = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
  return { header, secrets: basicSecrets({ Authorization: header }) };
}

/**
 * Asks the strategy, checks what it returned, and assembles the request. Throws
 * — before anything is sent — whatever the strategy threw, or a
 * `ClientAuthenticationResultError` for a result that cannot be sent.
 */
export async function prepareTokenRequest(
  grant: GrantRequest,
  auth: TokenRequestAuth,
): Promise<PreparedTokenRequest> {
  // Valid when the provider handed it over is not valid for every request
  // that follows: refused before the strategy is asked or anything is sent.
  if (auth.material && auth.notAfter !== undefined) {
    assertNotExpired(auth.notAfter);
  }
  // The token endpoint a client assertion names as its audience (RFC 7523):
  // a token request's own endpoint; for the device initiation, the one the
  // provider gave — never the device endpoint, which Keycloak refuses as aud.
  const tokenEndpoint =
    grant.grantType === 'device_authorization'
      ? auth.tokenEndpoint
      : grant.endpoint;
  const draft: ITokenRequestDraft = {
    endpoint: grant.endpoint,
    ...(auth.mtlsEndpoint === undefined
      ? {}
      : { mtlsEndpoint: auth.mtlsEndpoint }),
    ...(tokenEndpoint === undefined ? {} : { tokenEndpoint }),
    clientId: grant.clientId,
    grantType: grant.grantType,
  };
  const result: ITokenRequestAuthentication | null | undefined =
    await auth.strategy.authenticate(draft);
  if (!result || typeof result !== 'object') unusable();

  const parameters = stringRecord(result.parameters);
  const added = stringRecord(result.headers);
  const url = targetUrl(grant.endpoint, result.endpoint, auth.material);

  const body = new URLSearchParams(grant.parameters);
  for (const [name, value] of Object.entries(parameters)) {
    if (grant.parameters.has(name)) unusable();
    body.append(name, value);
  }
  const own = ['Content-Type', ...Object.keys(grant.headers ?? {})].map((h) =>
    h.toLowerCase(),
  );
  for (const [name, value] of Object.entries(added)) {
    if (
      own.includes(name.toLowerCase()) ||
      value.includes('\r') ||
      value.includes('\n')
    ) {
      unusable();
    }
  }

  const config: AxiosRequestConfig = {
    method: 'post',
    url,
    headers: { ...added, 'Content-Type': FORM, ...grant.headers },
    data: body.toString(),
    // A redirect would re-send the secret or the assertion, and present the
    // certificate, to wherever it points, past every check above.
    maxRedirects: 0,
  };
  if (grant.timeout !== undefined) config.timeout = grant.timeout;
  if (auth.material) config.httpsAgent = agentFor(auth.material);

  const secrets: Record<string, string> = {};
  for (const name of SECRET_PARAMETERS) {
    const value = parameters[name];
    if (value) secrets[name] = value;
  }
  return { config, secrets: { ...secrets, ...basicSecrets(added) } };
}

/** Grant parameters whose values are secrets the request itself sends. */
const SECRET_GRANT_PARAMETERS = [
  'refresh_token',
  'assertion',
  'code',
  'code_verifier',
  'subject_token',
  'actor_token',
  'passcode',
  'password',
  'device_code',
];

/** The secrets among a request's grant parameters, by parameter name. */
export function grantSecrets(params: URLSearchParams): Record<string, string> {
  const out: Record<string, string> = {};
  for (const name of SECRET_GRANT_PARAMETERS) {
    const value = params.get(name);
    if (value !== null) out[name] = value;
  }
  return out;
}

/** Below this many characters a secret is shown by its length only. */
const PREPARED_MIN = 16;
/** How many characters of each end of a secret `authDebug` shows. */
const PREPARED_EDGE = 4;

/**
 * The one way a secret reaches a log line (spec §6, "The secret preparer,
 * not a redactor"): called at the point of logging with the secret as a
 * separate value, never applied to a finished line. Without `authDebug`,
 * `<redacted, N chars>`; with it, a secret under 16 characters the same,
 * else its first 4 and last 4 characters around the marker,
 * `abcd…wxyz <redacted, N chars>`. N and the edges count whole characters
 * (code points), so no surrogate pair is split. No regex.
 */
export function prepareSecret(value: string, authDebug: boolean): string {
  const characters = [...value];
  const marker = `<redacted, ${characters.length} chars>`;
  if (authDebug !== true || characters.length < PREPARED_MIN) return marker;
  const head = characters.slice(0, PREPARED_EDGE).join('');
  const tail = characters.slice(-PREPARED_EDGE).join('');
  return `${head}…${tail} ${marker}`;
}

/** What of a failed request a site's own handling reads. */
export interface TokenRequestFailure extends Error {
  isAxiosError?: true;
  code?: string;
  status?: number;
  response?: {
    status?: unknown;
    statusText?: unknown;
    data?: OAuthErrorFields;
  };
}

/**
 * The failure without the request: an AxiosError carries its config (the
 * httpsAgent and its key, PFX and passphrase; the form body with an assertion,
 * a secret or a refresh token; the Authorization header) on itself, on
 * `request` and on `response.config`. What is rethrown is a new `AxiosError`
 * — `instanceof AxiosError` and `axios.isAxiosError` hold — built from what the
 * sites read and nothing else: a rebuilt `message` (axios's "Request failed
 * with status code N", or fixed words with the code), `code`, `status`, and a
 * response of `status`, an empty `statusText` (the reason phrase is the
 * server's text), empty `headers` and `data` reduced to the OAuth `error`
 * when it is a registered code — the server's free text (`error_description`,
 * `error_uri`) and an unregistered code are dropped: a server may echo the
 * request in them, in encodings no redaction can enumerate. They reach no
 * error and no log line. No `config`, `request` or
 * `cause` is set, so `toJSON()`, which reads `this.config`, serialises none.
 * Not only an axios failure: every rejection is replaced (`reduce`).
 */
export function withoutRequest(error: unknown): AxiosError {
  try {
    return reduce(error);
  } catch {
    // Nothing of a value whose reading throws is kept.
    return new AxiosError('the token request failed');
  }
}

/**
 * Every rejection is replaced, whatever it is: an axios failure, or anything
 * else that reached the request's promise — a consumer's response
 * interceptor throwing the server's `error_description`, a primitive, a
 * Proxy, an object whose getters throw. Only facts read through `readSafely`
 * and validated survive: an integer status, an allowlisted code, a registered
 * OAuth `error`. The original is never kept, not even as `cause` (which
 * `util.inspect` prints).
 */
/** axios's own error codes: its fixed words, kept on the replacement. */
const AXIOS_CODES: ReadonlySet<string> = new Set([
  AxiosError.ERR_FR_TOO_MANY_REDIRECTS,
  AxiosError.ERR_BAD_OPTION_VALUE,
  AxiosError.ERR_BAD_OPTION,
  AxiosError.ERR_NETWORK,
  AxiosError.ERR_DEPRECATED,
  AxiosError.ERR_BAD_RESPONSE,
  AxiosError.ERR_BAD_REQUEST,
  AxiosError.ERR_NOT_SUPPORT,
  AxiosError.ERR_INVALID_URL,
  AxiosError.ERR_CANCELED,
  AxiosError.ECONNABORTED,
  AxiosError.ETIMEDOUT,
]);

function reduce(error: unknown): AxiosError {
  // A cancellation stays one — `axios.isCancel` and `axios.isAxiosError`
  // both hold — in fixed words, with nothing of the original.
  if (readSafely(error, '__CANCEL__') === true) {
    return new CanceledError('the token request was canceled');
  }
  const rawCode = readSafely(error, 'code');
  const namedCode = allowlistedCode(rawCode);
  const code =
    namedCode ??
    (typeof rawCode === 'string' && AXIOS_CODES.has(rawCode)
      ? rawCode
      : undefined);
  const response = readSafely(error, 'response');
  const hasResponse = !!response && typeof response === 'object';
  const status =
    integerStatus(readSafely(response, 'status')) ??
    integerStatus(readSafely(error, 'status'));
  // The message is rebuilt, never copied: axios's own words for a status, else
  // fixed words with the code. Nothing of the server (a reason phrase, a body)
  // or of the request (a URL) can be in it.
  const message =
    status !== undefined
      ? `Request failed with status code ${status}`
      : `the token request failed${namedCode ? ` (${namedCode})` : ''}`;
  // AxiosResponse requires a config, and this one has none on purpose: the
  // config carries the agent's key, the form body and Authorization.
  const reduced = hasResponse
    ? ({
        status,
        // The reason phrase is the server's free text: it may echo a secret.
        statusText: '',
        headers: {},
        data: registeredOnly(readSafely(response, 'data')),
      } as unknown as AxiosResponse)
    : undefined;
  const failure = new AxiosError(message, code, undefined, undefined, reduced);
  if (failure.status === undefined && status !== undefined) {
    failure.status = status;
  }
  return failure;
}

/**
 * What of an error body stays on a thrown error: the OAuth `error` when it is
 * a registered code (a consumer, and the device poll, read it), nothing else;
 * a body that is not an object becomes undefined.
 */
function registeredOnly(data: unknown): OAuthErrorFields | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const error = registeredOAuthError(readSafely(data, 'error'));
  return error === undefined ? {} : { error };
}

/**
 * Runs a log call for a token site where a logger that throws must change
 * nothing: inside a catch, the failure the site rethrows — already replaced
 * by safe facts — must not be replaced by whatever the consumer's logger
 * threw.
 */
export function logQuietly(write: () => void): void {
  try {
    write();
  } catch {
    // The site's own outcome is what the caller needs.
  }
}

/** Where a site's failed request is noted: one debug line of safe facts. */
export interface TokenRequestDiagnostics {
  /**
   * TEMPORARY (removed with this interface in Task 21): never `'site'`, so
   * `arm` alone tells 5.4.2's diagnostics from a `TokenRequestSite`.
   */
  readonly arm?: undefined;
  /** The site's logger; without one, no line. */
  readonly logger?: ILogger | null | undefined;
  /** The site, naming the line. */
  readonly label: string;
}

/** The device poll's answers while it waits: the protocol, not a failure. */
const WAITING = new Set(['authorization_pending', 'slow_down']);

/**
 * A failed request in one `debug` line through the site's logger: the HTTP
 * status and the OAuth `error` when it is a registered code — never the
 * server's free text (`error_description`, `error_uri`), which may echo any
 * secret of the request in an encoding no redaction can enumerate, nor an
 * unregistered code. No line for the device poll's waiting answers, none
 * without a logger; a logger that throws is ignored, so the failure the site
 * throws is never replaced.
 */
export function logRefusedRequest(
  diagnostics: TokenRequestDiagnostics | undefined,
  status: unknown,
  data: unknown,
): void {
  const logger = diagnostics?.logger;
  if (!logger) return;
  try {
    const error = registeredOAuthError(readSafely(data, 'error'));
    if (error !== undefined && WAITING.has(error)) return;
    logger.debug(
      `${diagnostics.label}: the token endpoint refused the request`,
      {
        status: integerStatus(status),
        ...(error === undefined ? {} : { error }),
      },
    );
  } catch {
    // The site's failure is what the caller needs.
  }
}

/**
 * A token site, as the error contract's conversion point reads it (spec §6):
 * what it was doing, through which grant, where its one line goes, whether
 * its consumer opted into `sent` (`authDebug`), and every secret its request
 * carried — each passed by the site, never looked up. The server's text is
 * never read for any site.
 */
export interface TokenRequestSite {
  /**
   * TEMPORARY (Decision D6; removed in Task 21 with the legacy arm): the
   * explicit discriminant `sendTokenRequest` dispatches on — never on which
   * other properties an argument carries.
   */
  readonly arm: 'site';
  readonly operation: Operation;
  readonly grant?: OAuth2GrantType | undefined;
  /** The provider's logger; no logger → no line, nothing else changes. */
  readonly logger?: ILogger | null | undefined;
  /**
   * The consumer's `authDebug === true`; anything else → the safe-facts line
   * only. Either way the server's text is never read.
   */
  readonly authDebug: boolean;
  /**
   * Every secret this request carried, by name: `grantSecrets(params)` and
   * the configured `client_secret` — what the `authDebug` line names in
   * `sent`, each through `prepareSecret`.
   */
  readonly secrets: SentSecrets;
  /**
   * The site's own Basic header on the path without a strategy, as built by
   * `legacyBasic()` — never assembled by the site itself.
   */
  readonly basic?: LegacyBasic | undefined;
}

/**
 * What a site receives of a successful answer (spec §6): an integer status
 * and a plain `data` of `ANSWER_FIELDS` — never the object axios handed over,
 * and never the server's free text (`error_description`, `error_uri`), with
 * or without `authDebug`.
 */
export interface TokenResponseSnapshot<T = Record<string, string | number>> {
  readonly status: number | undefined;
  readonly data: T;
}

/**
 * `sent` of the `authDebug` line: every secret the request carried, by name,
 * each through `prepareSecret` — joined in one place for both lines
 * (`sendTokenRequest` and `rejectMissingToken`), so the two cannot drift:
 * the site's own (grant and configured client secret), its legacy Basic
 * credential, and the strategy's. Each is passed by the site, never looked
 * up, and an absent or empty one is not named.
 */
function sentOf(
  site: TokenRequestSite,
  prepared: PreparedTokenRequest | undefined,
): Record<string, string> {
  const sent: Record<string, string> = {};
  for (const source of [site.secrets, site.basic?.secrets, prepared?.secrets]) {
    for (const [name, value] of Object.entries(source ?? {})) {
      if (typeof value === 'string' && value !== '' && !(name in sent)) {
        sent[name] = prepareSecret(value, debugging(site));
      }
    }
  }
  return sent;
}

/** Whether the consumer opted into `sent`: `true` itself, nothing else. */
const debugging = (site: TokenRequestSite): boolean => site.authDebug === true;

/** The operation and grant of a site, as the facts of its failure. */
function factsOf(site: TokenRequestSite): {
  operation: Operation;
  grant?: OAuth2GrantType;
} {
  return {
    operation: site.operation,
    ...(site.grant === undefined ? {} : { grant: site.grant }),
  };
}

const INCOMPLETE = ' returned an incomplete response';

/**
 * The operation's phrase — auth-errors' own subject of its words
 * (`the passcode exchange`, `authorization_code token request`), read from
 * the words it renders, so a line and the failure name the operation alike.
 */
function phraseOf(site: TokenRequestSite): string {
  const { reason } = render('request-failed', {
    ...factsOf(site),
    problem: 'incomplete-response',
  });
  return reason.endsWith(INCOMPLETE)
    ? reason.slice(0, -INCOMPLETE.length)
    : 'the token request';
}

/**
 * A failed request on the new arm: its one line, then the failure (spec §6).
 * The facts are read once, each through `readSafely`: an integer status, a
 * registered OAuth `error`, an allowlisted code. By default the line is
 * 5.4.2's safe facts (`status`, `error` when registered) plus an allowlisted
 * `code` (a recorded addition); only with `authDebug`, instead, the line
 * `[<operation>] token endpoint said` with the same facts plus `sent`.
 * Nothing of the body is read beyond `error`, in either mode — never
 * `error_description` / `error_uri`. None for the device poll's waiting
 * answers, none without a logger, a throwing logger swallowed. The failure
 * is `tls` for an allowlisted TLS code, else `request-failed` — `refused`
 * with an HTTP status, `no-response` without one — and carries no body, no
 * cause, nothing of the request.
 */
function failedRequest(
  error: unknown,
  site: TokenRequestSite,
  prepared: PreparedTokenRequest | undefined,
): AuthProviderFailure {
  try {
    const response = readSafely(error, 'response');
    const body = readSafely(response, 'data');
    const rawStatus = readSafely(response, 'status');
    const oauthError = registeredOAuthError(readSafely(body, 'error'));
    const rawCode = readSafely(error, 'code');
    const tls = tlsFailureCode(error);
    const code = allowlistedCode(rawCode);
    const systemCode = isSystemCode(rawCode) ? rawCode : undefined;
    const status = httpStatus(rawStatus);

    const logger = site.logger;
    if (logger && !(oauthError !== undefined && WAITING.has(oauthError))) {
      logQuietly(() => {
        const safe = {
          status: integerStatus(rawStatus),
          ...(oauthError === undefined ? {} : { error: oauthError }),
          ...(code === undefined ? {} : { code }),
        };
        if (debugging(site)) {
          logger.debug(`[${site.operation}] token endpoint said`, {
            ...safe,
            sent: sentOf(site, prepared),
          });
        } else {
          logger.debug(
            `${phraseOf(site)}: the token endpoint refused the request`,
            safe,
          );
        }
      });
    }

    if (tls !== undefined) {
      return new AuthProviderFailure(
        authError.tls({ ...factsOf(site), code: tls }),
      );
    }
    return new AuthProviderFailure(
      authError['request-failed']({
        ...factsOf(site),
        ...(status === undefined
          ? { problem: 'no-response' }
          : {
              problem: 'refused',
              status,
              ...(isOAuthErrorCode(oauthError) ? { oauthError } : {}),
            }),
        ...(systemCode === undefined ? {} : { code: systemCode }),
      }),
    );
  } catch {
    return new AuthProviderFailure(
      authError['request-failed']({
        operation: site.operation,
        problem: 'no-response',
      }),
    );
  }
}

/**
 * Sends one request — the prepared one when a strategy was given, else the
 * site's own `asToday`.
 *
 * TEMPORARY two arms (Decision D6; the legacy arm goes in Task 21), told
 * apart by the explicit discriminant `arm`:
 * - a `TokenRequestSite` (`arm: 'site'`): every failure becomes an
 *   `AuthProviderFailure` after the site's one line (`failedRequest`); an
 *   answer becomes a `TokenResponseSnapshot`, one that cannot be read a
 *   `request-failed` `incomplete-response` failure with the operation only;
 * - 5.4.2's `TokenRequestDiagnostics`, or nothing: 5.4.2 exactly — the failure
 *   thrown without the request (`withoutRequest`), its safe facts noted
 *   (`logRefusedRequest`), the answer a snapshot (`snapshotOf`).
 */
export function sendTokenRequest<T>(
  prepared: PreparedTokenRequest | undefined,
  asToday: () => Promise<AxiosResponse<T>>,
  site: TokenRequestSite,
): Promise<TokenResponseSnapshot<T>>;
export function sendTokenRequest<T>(
  prepared: PreparedTokenRequest | undefined,
  asToday: () => Promise<AxiosResponse<T>>,
  diagnostics?: TokenRequestDiagnostics,
): Promise<AxiosResponse<T>>;
export async function sendTokenRequest<T>(
  prepared: PreparedTokenRequest | undefined,
  asToday: () => Promise<AxiosResponse<T>>,
  third?: TokenRequestDiagnostics | TokenRequestSite,
): Promise<AxiosResponse<T> | TokenResponseSnapshot<T>> {
  if (third?.arm === 'site') {
    return sendForSite<T>(prepared, asToday, third);
  }
  return sendAsLegacy<T>(prepared, asToday, third);
}

/** 5.4.2's `sendTokenRequest`, unchanged (the legacy arm). */
async function sendAsLegacy<T>(
  prepared: PreparedTokenRequest | undefined,
  asToday: () => Promise<AxiosResponse<T>>,
  diagnostics: TokenRequestDiagnostics | undefined,
): Promise<AxiosResponse<T>> {
  let response: unknown;
  try {
    response = prepared ? await axios<T>(prepared.config) : await asToday();
  } catch (error) {
    const response = readSafely(error, 'response');
    logRefusedRequest(
      diagnostics,
      readSafely(response, 'status'),
      readSafely(response, 'data'),
    );
    throw withoutRequest(error);
  }
  return snapshotOf<T>(response);
}

/** The new arm: a site's failure, or its snapshot. */
async function sendForSite<T>(
  prepared: PreparedTokenRequest | undefined,
  asToday: () => Promise<AxiosResponse<T>>,
  site: TokenRequestSite,
): Promise<TokenResponseSnapshot<T>> {
  let response: unknown;
  try {
    response = prepared ? await axios<T>(prepared.config) : await asToday();
  } catch (error) {
    throw failedRequest(error, site, prepared);
  }
  try {
    return siteSnapshot<T>(response);
  } catch {
    throw new AuthProviderFailure(
      authError['request-failed']({
        operation: site.operation,
        problem: 'incomplete-response',
      }),
    );
  }
}

/**
 * The fields a token site reads from an answer: the token response's (RFC
 * 6749 §5.1, OIDC Core §3.1.3.3), the device authorization response's (RFC
 * 8628 §3.2) and the OAuth `error`.
 */
const ANSWER_FIELDS = [
  'access_token',
  'refresh_token',
  'id_token',
  'token_type',
  'expires_in',
  'scope',
  'device_code',
  'user_code',
  'verification_uri',
  'verification_uri_complete',
  'interval',
  'error',
] as const;

/**
 * What a site may read of a successful answer: an integer status and a plain
 * object of the expected fields that are strings or numbers, each read
 * through `readSafely` — never the object axios (or a consumer's response
 * interceptor) handed over, whose getters, Proxy traps or `toJSON` could
 * throw the server's text into a site's parsing. A field whose read throws
 * reads as absent; anything that still throws here is replaced by a safe
 * error with no cause.
 */
function snapshotOf<T>(response: unknown): AxiosResponse<T> {
  try {
    return {
      status: integerStatus(readSafely(response, 'status')),
      statusText: '',
      headers: {},
      data: answerData(readSafely(response, 'data')),
    } as unknown as AxiosResponse<T>;
  } catch {
    throw new AxiosError('the token request failed');
  }
}

/** The expected fields of an answer's body that are strings or numbers. */
function answerData(raw: unknown): Record<string, string | number> {
  const data: Record<string, string | number> = {};
  for (const field of ANSWER_FIELDS) {
    const value = readSafely(raw, field);
    if (typeof value === 'string' || typeof value === 'number') {
      data[field] = value;
    }
  }
  return data;
}

/**
 * The new arm's snapshot: `snapshotOf`'s boundary — an integer status and
 * the expected fields only, never the server's text. May throw: the caller
 * replaces any throw.
 */
function siteSnapshot<T>(response: unknown): TokenResponseSnapshot<T> {
  return {
    status: integerStatus(readSafely(response, 'status')),
    data: answerData(readSafely(response, 'data')) as unknown as T,
  };
}

/**
 * The lead of the missing-token line: 5.4.2's own at the UAA code exchange
 * (`browserAuth.ts:148-161` at 5.4.2, kept verbatim), else
 * `<operation phrase> failed`.
 */
function missingTokenLead(site: TokenRequestSite): string {
  return site.operation === 'code-exchange'
    ? 'Token exchange failed'
    : `${phraseOf(site)} failed`;
}

/**
 * A 2xx that carries no usable token (spec §6, C8): one guarded line at the
 * level the site passes — by default the safe facts only,
 * `<lead>: status <n>, error: "<code>"` (or `no error given`; at the code
 * exchange 5.4.2's `error` line verbatim) — and, with `authDebug`, the same
 * message with `{ status, error?, sent }` beside it, `sent` joined exactly
 * as `sendTokenRequest` joins it (`sentOf`). Nothing of the body is read but
 * the registered `error`. Then `request-failed` with the status and the
 * problem; nothing of the body enters it.
 */
export function rejectMissingToken(
  site: TokenRequestSite,
  prepared: PreparedTokenRequest | undefined,
  snapshot: TokenResponseSnapshot<unknown>,
  problem: 'no-access-token' | 'incomplete-response',
  level: 'error' | 'debug',
): never {
  const status = integerStatus(readSafely(snapshot, 'status'));
  const error = registeredOAuthError(
    readSafely(readSafely(snapshot, 'data'), 'error'),
  );
  const logger = site.logger;
  if (logger) {
    logQuietly(() => {
      const message = `${missingTokenLead(site)}: status ${status}, error: ${error === undefined ? 'no error given' : JSON.stringify(error)}`;
      if (debugging(site)) {
        logger[level](message, {
          status,
          ...(error === undefined ? {} : { error }),
          sent: sentOf(site, prepared),
        });
      } else {
        logger[level](message);
      }
    });
  }
  const httpCode = httpStatus(status);
  throw new AuthProviderFailure(
    authError['request-failed']({
      ...factsOf(site),
      problem,
      ...(httpCode === undefined ? {} : { status: httpCode }),
    }),
  );
}

/**
 * A failed token request as a site rethrows it: a `TokenEndpointError`
 * carrying the safe facts — the HTTP status, the OAuth `error` when it is a
 * registered code, an allowlisted system code — so a refusal and a log line
 * can name them. With a response, the message is `<label> (<status>)` and,
 * when the server gave a registered code, `: <code>`; the server's
 * description never.
 * Without one, `<label>: ` and fixed words (`loggedError`). The cause is
 * what `sendTokenRequest` threw: its safe replacement, never the original.
 */
export function tokenEndpointError(
  label: string,
  error: unknown,
): TokenEndpointError {
  // Guarded reads: a getter or a Proxy reads as absent.
  const response = readSafely(error, 'response');
  const status = integerStatus(readSafely(response, 'status'));
  if (status !== undefined) {
    const oauthError = registeredOAuthError(
      readSafely(readSafely(response, 'data'), 'error'),
    );
    return new TokenEndpointError(
      `${label} (${status})${oauthError === undefined ? '' : `: ${oauthError}`}`,
      { status, oauthError },
      { cause: error },
    );
  }
  const code = allowlistedCode(readSafely(error, 'code'));
  return new TokenEndpointError(
    `${label}: ${loggedError(error, 'the token request').error}`,
    { code },
    { cause: error },
  );
}
