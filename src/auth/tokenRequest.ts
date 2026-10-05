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
} from 'axios';
import { ClientAuthenticationResultError } from '../errors/ClientAuthenticationError';
import { TokenEndpointError } from '../errors/TokenEndpointError';
import { assertNotExpired } from './certificateMaterial';
import { allowlistedCode, integerStatus, readSafely } from './knownCodes';
import {
  type OAuthErrorFields,
  oauthErrorFields,
  registeredOAuthError,
} from './oauthErrorBody';
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
 * The one place a site without a strategy builds its Basic header: the
 * secrets come from the same `basicSecrets()` a strategy's Basic credential
 * goes through, so both paths redact the same forms, and a site cannot send
 * the header without them.
 */
export function legacyBasic(
  clientId: string,
  clientSecret: string,
): LegacyBasic {
  const header = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`;
  return { header, secrets: basicSecrets({ Authorization: header }) };
}

/**
 * Every secret one request carried, joined in one place: the site's own (its
 * grant's, its configured client secret), its legacy Basic credential, and
 * what the strategy sent. Every redaction of that request's answer — a failed
 * one in `sendTokenRequest`, a site's `tokenEndpointError`, a logged body of a
 * success without a token — joins through here, so none can drift.
 */
export function requestSecrets(
  sent: readonly (string | undefined)[],
  basic: LegacyBasic | undefined,
  prepared: PreparedTokenRequest | undefined,
): (string | undefined)[] {
  return [...sent, ...(basic?.secrets ?? []), ...(prepared?.secrets ?? [])];
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
 * request in them, in encodings no redaction can enumerate. They reach only
 * the site's debug line (`logServerWords`). No `config`, `request` or
 * `cause` is set, so `toJSON()`, which reads `this.config`, serialises none.
 */
function withoutRequest(error: unknown): unknown {
  try {
    return reduce(error);
  } catch {
    // A value whose reading throws: nothing of it is kept.
    return new AxiosError('the token request failed');
  }
}

function reduce(error: unknown): unknown {
  if (!error || typeof error !== 'object') return error;
  const raw = error as Record<string, unknown>;
  if (!('config' in raw) && !('request' in raw) && !('response' in raw)) {
    return error;
  }
  const code = typeof raw.code === 'string' ? raw.code : undefined;
  const namedCode = allowlistedCode(code);
  const response = raw.response as Record<string, unknown> | undefined;
  const status =
    response && typeof response === 'object' ? response.status : undefined;
  // The message is rebuilt, never copied: axios's own words for a status, else
  // fixed words with the code. Nothing of the server (a reason phrase, a body)
  // or of the request (a URL) can be in it.
  const message =
    typeof status === 'number'
      ? `Request failed with status code ${status}`
      : `the token request failed${namedCode ? ` (${namedCode})` : ''}`;
  // AxiosResponse requires a config, and this one has none on purpose: the
  // config carries the agent's key, the form body and Authorization.
  const reduced =
    response && typeof response === 'object'
      ? ({
          status,
          // The reason phrase is the server's free text: it may echo a secret.
          statusText: '',
          headers: {},
          data: registeredOnly(response.data),
        } as unknown as AxiosResponse)
      : undefined;
  const failure = new AxiosError(message, code, undefined, undefined, reduced);
  if (failure.status === undefined && typeof raw.status === 'number') {
    failure.status = raw.status;
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

/** Where a site's failed request may say what the server said: one debug line. */
export interface TokenRequestDiagnostics {
  /** The site's logger; without one, no line. */
  readonly logger?: ILogger | null | undefined;
  /** The site, naming the line. */
  readonly label: string;
}

/** The device poll's answers while it waits: the protocol, not a failure. */
const WAITING = new Set(['authorization_pending', 'slow_down']);

/**
 * The server's own words about a failed request — `error`,
 * `error_description`, `error_uri`, every secret the request carried redacted
 * (`oauthErrorFields`) — in one `debug` line through the site's logger, the
 * only place they go. No logger, no line; a logger that throws is ignored, so
 * the failure the site throws is never replaced.
 */
export function logServerWords(
  diagnostics: TokenRequestDiagnostics | undefined,
  status: unknown,
  data: unknown,
  secrets: readonly (string | undefined)[],
): void {
  const logger = diagnostics?.logger;
  if (!logger) return;
  try {
    const fields = oauthErrorFields(data, secrets);
    if (!fields || Object.keys(fields).length === 0) return;
    if (fields.error !== undefined && WAITING.has(fields.error)) return;
    logger.debug(`${diagnostics.label}: the token endpoint said`, {
      status: integerStatus(status),
      ...fields,
    });
  } catch {
    // The site's failure is what the caller needs.
  }
}

/**
 * Sends one request — the prepared one when a strategy was given, else the
 * site's own `asToday` — and on failure throws it without the request
 * (`withoutRequest`). The request itself is not changed on either path.
 *
 * @param sent the secrets the site itself put in the request (a refresh
 *   token, a code, an assertion, a client secret); with the site's own Basic
 *   credential and what the strategy added, they are redacted from the error
 *   body that stays on the error.
 * @param basic the site's own Basic header without a strategy (`legacyBasic`).
 * @param diagnostics where the server's own words go (`logServerWords`): the
 *   thrown error carries none of them.
 */
export async function sendTokenRequest<T>(
  prepared: PreparedTokenRequest | undefined,
  asToday: () => Promise<AxiosResponse<T>>,
  sent: readonly (string | undefined)[] = [],
  basic?: LegacyBasic,
  diagnostics?: TokenRequestDiagnostics,
): Promise<AxiosResponse<T>> {
  try {
    return prepared ? await axios<T>(prepared.config) : await asToday();
  } catch (error) {
    const response = readSafely(error, 'response');
    logServerWords(
      diagnostics,
      readSafely(response, 'status'),
      readSafely(response, 'data'),
      requestSecrets(sent, basic, prepared),
    );
    throw withoutRequest(error);
  }
}

/**
 * A failed token request as a site rethrows it: a `TokenEndpointError`
 * carrying the safe facts — the HTTP status, the OAuth `error` when it is a
 * registered code, an allowlisted system code — so a refusal and a log line
 * can name them. With a response, the message is `<label> (<status>)` and,
 * when the server gave a registered code, `: <code>`; the server's
 * description never (it went to the site's debug line, `logServerWords`).
 * Without one, `<label>: ` and fixed words (`loggedError`). The original is
 * the cause.
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
