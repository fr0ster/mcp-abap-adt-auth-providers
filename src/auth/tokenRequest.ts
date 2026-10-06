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
 * (`client-certificate` `expired`). What the strategy returned is
 * checked before anything is sent: a value that
 * is not a string, a header with a line break, a parameter or header that
 * would replace one of the site's own, an endpoint that is not an absolute `https:` URL —
 * each throws `client-authentication` `result-unsendable` (A5).
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
  OAuth2GrantType,
  Operation,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import axios, { type AxiosRequestConfig, type AxiosResponse } from 'axios';
import { abortedFailure } from './attempt';
import { assertNotExpired } from './certificateMaterial';
import { markHandled } from './handled';
import {
  allowlistedCode,
  integerStatus,
  readSafely,
  tlsFailureCode,
} from './knownCodes';
import { registeredOAuthError } from './oauthErrorBody';

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
}

export interface PreparedTokenRequest {
  /** The whole axios config: url, method, headers, data, and httpsAgent when set; never a timeout. */
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

/** A5: the strategy's result cannot be sent; nothing is. */
function unusable(): never {
  throw new AuthProviderFailure(
    authError['client-authentication']({ problem: 'result-unsendable' }),
  );
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
 * — before anything is sent — whatever the strategy threw, or
 * `client-authentication` `result-unsendable` for a result that cannot be
 * sent.
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

/**
 * A site's own secrets, by name: the grant's (`grantSecrets`) and the
 * configured client secret as `client_secret` when there is one.
 */
export function siteSecrets(
  params: URLSearchParams,
  clientSecret: string | undefined,
): Record<string, string> {
  return {
    ...grantSecrets(params),
    ...(clientSecret ? { client_secret: clientSecret } : {}),
  };
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

/**
 * Runs a log call for a token site where a logger that throws must change
 * nothing: inside a catch, the failure the site rethrows — already replaced
 * by safe facts — must not be replaced by whatever the consumer's logger
 * threw. A logger whose method answers a rejecting promise (an async
 * logger) must not leave an unhandled rejection either: a plain native
 * promise answered by `write` gets a no-op rejection handler, through the
 * `then` captured at load. A foreign thenable, a Promise subclass or a
 * Proxy gets none — handling it would run its code.
 */
export function logQuietly(write: () => unknown): void {
  try {
    const answered = write();
    markHandled(answered);
  } catch {
    // The site's own outcome is what the caller needs.
  }
}

/** The device poll's answers while it waits: the protocol, not a failure. */
const WAITING = new Set(['authorization_pending', 'slow_down']);

/**
 * What a provider tells every token site it calls (spec §6): its
 * `authDebug` — `true` itself, nothing else, read once by `BaseTokenProvider`
 * from its configuration, never from the environment — and its grant, the
 * `grant` fact of a failure. A site helper takes it as a parameter; without
 * one, `authDebug` is off and no grant is named.
 */
export interface TokenSiteOptions {
  readonly authDebug?: boolean | undefined;
  readonly grant?: OAuth2GrantType | undefined;
  /**
   * The signal of the attempt the request belongs to (spec §6b): its abort
   * cuts the request. Read only by the sites of an attempt's own requests
   * (`attemptSite`) — never by a refresh site (`tokenSite`), whose request
   * runs on after an abort so that its answer can still be committed.
   */
  readonly signal?: AbortSignal | undefined;
}

/**
 * A token site, as the error contract's conversion point reads it (spec §6):
 * what it was doing, through which grant, where its one line goes, whether
 * its consumer opted into `sent` (`authDebug`), and every secret its request
 * carried — each passed by the site, never looked up. The server's text is
 * never read for any site.
 */
export interface TokenRequestSite {
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
  /**
   * The attempt's signal, passed to axios as `signal` on both paths
   * (spec §6b). Absent by construction at every refresh site.
   */
  readonly signal?: AbortSignal | undefined;
}

/**
 * A site's description from the provider's options: the operation, the
 * secrets and the Basic credential are the site's own; `authDebug` is on only
 * for `true` itself. The options' `signal` is never read here: this is the
 * refresh sites' constructor (UAA, SAML, OIDC refresh), whose request is
 * never given the attempt's signal (spec §6b) — every other site is built by
 * `attemptSite`.
 */
export function tokenSite(
  operation: Operation,
  options: TokenSiteOptions | undefined,
  logger: ILogger | null | undefined,
  secrets: SentSecrets,
  basic?: LegacyBasic,
): TokenRequestSite {
  return {
    operation,
    ...(options?.grant === undefined ? {} : { grant: options.grant }),
    logger,
    authDebug: options?.authDebug === true,
    secrets,
    ...(basic === undefined ? {} : { basic }),
  };
}

/**
 * The site of an attempt's own request — every request but a refresh: the
 * same as `tokenSite`, plus the attempt's `signal` from the options, so the
 * attempt's abort cuts the request (spec §6b).
 */
export function attemptSite(
  operation: Operation,
  options: TokenSiteOptions | undefined,
  logger: ILogger | null | undefined,
  secrets: SentSecrets,
  basic?: LegacyBasic,
): TokenRequestSite {
  const site = tokenSite(operation, options, logger, secrets, basic);
  const signal = options?.signal;
  return signal === undefined ? site : { ...site, signal };
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
function factsOf(site: {
  readonly operation: Operation;
  readonly grant?: OAuth2GrantType | undefined;
}): {
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

/** The facts of a failed request, each read once through `readSafely`. */
interface RequestFacts {
  /** The integer status as the line names it (5.4.2: any integer). */
  readonly lineStatus: number | undefined;
  readonly oauthError: string | undefined;
  /** An allowlisted system or TLS code, as the line names it. */
  readonly code: string | undefined;
  readonly failure: AuthProviderFailure;
}

/**
 * A failed request's facts and its failure (spec §6): `tls` for an
 * allowlisted TLS code, else `request-failed` — `refused` with an HTTP
 * status and a registered `oauthError`, `no-response` without a status, an
 * allowlisted system code as `code`. Nothing of the body is read beyond a
 * registered `error`; the failure carries no body, no cause, nothing of the
 * request. Total: a value whose reading throws past `readSafely` becomes
 * `request-failed` `no-response` with the operation only.
 */
function readRequestFailure(
  error: unknown,
  facts: {
    readonly operation: Operation;
    readonly grant?: OAuth2GrantType | undefined;
  },
): RequestFacts {
  try {
    const response = readSafely(error, 'response');
    const rawStatus = readSafely(response, 'status');
    const oauthError = registeredOAuthError(
      readSafely(readSafely(response, 'data'), 'error'),
    );
    const rawCode = readSafely(error, 'code');
    const tls = tlsFailureCode(error);
    const systemCode = isSystemCode(rawCode) ? rawCode : undefined;
    const status = httpStatus(rawStatus);
    const failure =
      tls !== undefined
        ? new AuthProviderFailure(
            authError.tls({ ...factsOf(facts), code: tls }),
          )
        : new AuthProviderFailure(
            authError['request-failed']({
              ...factsOf(facts),
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
    return {
      lineStatus: integerStatus(rawStatus),
      oauthError,
      code: allowlistedCode(rawCode),
      failure,
    };
  } catch {
    return {
      lineStatus: undefined,
      oauthError: undefined,
      code: undefined,
      failure: new AuthProviderFailure(
        authError['request-failed']({
          operation: facts.operation,
          problem: 'no-response',
        }),
      ),
    };
  }
}

/**
 * A rejected request that is not a token site's — OIDC discovery — as its
 * failure: the same classification, no line (spec §6: discovery writes no
 * failure line).
 */
export function requestFailure(
  error: unknown,
  operation: Operation,
): AuthProviderFailure {
  return readRequestFailure(error, { operation }).failure;
}

/**
 * A failed request: its one line, then the failure (spec §6). By default the
 * line is 5.4.2's safe facts (`status`, `error` when registered) plus an
 * allowlisted `code` (a recorded addition); only with `authDebug`, instead,
 * the line `[<operation>] token endpoint said` with the same facts plus
 * `sent`. Nothing of the body is read beyond `error`, in either mode — never
 * `error_description` / `error_uri`. None for the device poll's waiting
 * answers, none without a logger, a throwing logger swallowed.
 */
function failedRequest(
  error: unknown,
  site: TokenRequestSite,
  prepared: PreparedTokenRequest | undefined,
): AuthProviderFailure {
  // The attempt's own abort cut the request: no refusal, no line — the
  // attempt is over, and its waiters were already answered `aborted`.
  if (site.signal?.aborted === true) return abortedFailure();
  const { lineStatus, oauthError, code, failure } = readRequestFailure(
    error,
    site,
  );
  const logger = site.logger;
  // Only the device poll's own waiting answers — a 400 — are the protocol.
  const waiting =
    site.operation === 'device-poll' &&
    lineStatus === 400 &&
    oauthError !== undefined &&
    WAITING.has(oauthError);
  if (logger && !waiting) {
    logQuietly(() => {
      const safe = {
        status: lineStatus,
        ...(oauthError === undefined ? {} : { error: oauthError }),
        ...(code === undefined ? {} : { code }),
      };
      // Returned, so an async logger's rejection is handled (logQuietly).
      if (debugging(site)) {
        return logger.debug(`[${site.operation}] token endpoint said`, {
          ...safe,
          sent: sentOf(site, prepared),
        });
      }
      return logger.debug(
        `${phraseOf(site)}: the token endpoint refused the request`,
        safe,
      );
    });
  }
  return failure;
}

/**
 * Sends one request — the prepared one when a strategy was given, else the
 * site's own `asToday` — and answers a snapshot of it (spec §6). Every
 * failure becomes an `AuthProviderFailure` after the site's one line
 * (`failedRequest`); an answer that cannot be read becomes `request-failed`
 * `incomplete-response` with the operation only.
 */
export async function sendTokenRequest<T>(
  prepared: PreparedTokenRequest | undefined,
  asToday: (signal: AbortSignal | undefined) => Promise<AxiosResponse<T>>,
  site: TokenRequestSite,
): Promise<TokenResponseSnapshot<T>> {
  // The attempt's signal, on both paths (spec §6b); a refresh site has none.
  const signal = site.signal;
  let response: unknown;
  try {
    response = prepared
      ? await axios<T>(
          signal === undefined
            ? prepared.config
            : { ...prepared.config, signal },
        )
      : await asToday(signal);
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
 * What a site may read of a successful answer: an integer status and a plain
 * object of the expected fields that are strings or numbers, each read
 * through `readSafely` — never the object axios (or a consumer's response
 * interceptor) handed over, whose getters, Proxy traps or `toJSON` could
 * throw the server's text into a site's parsing. May throw: the caller
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
      // Returned, so an async logger's rejection is handled (logQuietly).
      if (debugging(site)) {
        return logger[level](message, {
          status,
          ...(error === undefined ? {} : { error }),
          sent: sentOf(site, prepared),
        });
      }
      return logger[level](message);
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
