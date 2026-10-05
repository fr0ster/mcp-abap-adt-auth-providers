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
import { allowlistedCode, integerStatus, readSafely } from './knownCodes';
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
   * What the strategy sent that must never come back out of an error body:
   * `client_secret`, `client_assertion`, and a Basic credential.
   */
  readonly secrets: readonly string[];
}

const FORM = 'application/x-www-form-urlencoded';
/**
 * Parameters whose values are secrets: they join the redaction list, with the
 * credential of an `Authorization: Basic` header (`basicSecrets`). That is the
 * limit of what is recognised: a custom strategy's secret in any other
 * parameter or header is not known to be one, and is not redacted.
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

/**
 * The secrets of a `Basic` credential: the base64 credential and the secret
 * as sent. Redaction tries each in every form a server may echo — its
 * form-decoding among them, which is the original for `clientSecretBasic`'s
 * `'form'`, and what a decoding server read for its `'raw'`.
 */
function basicSecrets(headers: Record<string, string>): string[] {
  const out: string[] = [];
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() !== 'authorization') continue;
    const credential = /^Basic\s+(\S+)$/i.exec(value)?.[1];
    if (credential === undefined) continue;
    out.push(credential);
    const decoded = Buffer.from(credential, 'base64').toString();
    const colon = decoded.indexOf(':');
    if (colon >= 0 && colon < decoded.length - 1) {
      out.push(decoded.slice(colon + 1));
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
  /** What `basicSecrets()` extracts from it: the base64 credential and the secret. */
  readonly secrets: readonly string[];
}

/**
 * The one place a site without a strategy builds its Basic header. Its
 * secrets come from the same `basicSecrets()` a strategy's Basic credential
 * goes through, for any redaction of what a server says back — 5.4.2 writes
 * none of the server's words anywhere, so nothing reads them yet.
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
    if (own.includes(name.toLowerCase()) || /[\r\n]/.test(value)) unusable();
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

  const secrets = [
    ...SECRET_PARAMETERS.map((name) => parameters[name]).filter(
      (value): value is string => !!value,
    ),
    ...basicSecrets(added),
  ];
  return { config, secrets };
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

/** The secret values among a request's grant parameters. */
export function grantSecrets(params: URLSearchParams): string[] {
  return SECRET_GRANT_PARAMETERS.flatMap((name) => params.getAll(name));
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
 * Sends one request — the prepared one when a strategy was given, else the
 * site's own `asToday` — and on failure throws it without the request
 * (`withoutRequest`). The request itself is not changed on either path.
 *
 * @param diagnostics where the failure is noted (`logRefusedRequest`): safe
 *   facts only, like the thrown error.
 */
export async function sendTokenRequest<T>(
  prepared: PreparedTokenRequest | undefined,
  asToday: () => Promise<AxiosResponse<T>>,
  diagnostics?: TokenRequestDiagnostics,
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
    const raw = readSafely(response, 'data');
    const data: Record<string, string | number> = {};
    for (const field of ANSWER_FIELDS) {
      const value = readSafely(raw, field);
      if (typeof value === 'string' || typeof value === 'number') {
        data[field] = value;
      }
    }
    return {
      status: integerStatus(readSafely(response, 'status')),
      statusText: '',
      headers: {},
      data,
    } as unknown as AxiosResponse<T>;
  } catch {
    throw new AxiosError('the token request failed');
  }
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
