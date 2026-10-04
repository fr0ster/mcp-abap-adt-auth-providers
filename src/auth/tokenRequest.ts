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
import axios, {
  AxiosError,
  type AxiosRequestConfig,
  type AxiosResponse,
} from 'axios';
import { ClientAuthenticationResultError } from '../errors/ClientAuthenticationError';
import { assertNotExpired } from './certificateMaterial';
import { type OAuthErrorFields, oauthErrorFields } from './oauthErrorBody';

/** What a site is given to authenticate one request with a strategy. */
export interface TokenRequestAuth {
  readonly strategy: IClientAuthentication;
  /** The strategy's TLS material, already pinned by the provider. */
  readonly material?: ICertificateMaterial;
  /**
   * The pinned certificate's `notAfter` (epoch ms). Checked before every
   * request that presents the material — a device poll may outlive it — so no
   * expired certificate is sent.
   */
  readonly notAfter?: number;
  /** The server's mTLS alias of this request's endpoint (RFC 8705 §5), when it published one. */
  readonly mtlsEndpoint?: string;
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
  readonly headers?: Readonly<Record<string, string>>;
  readonly timeout?: number;
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

/** The secret of a `Basic` credential, in both forms a server may echo. */
function basicSecrets(headers: Record<string, string>): string[] {
  const out: string[] = [];
  for (const [name, value] of Object.entries(headers)) {
    if (name.toLowerCase() !== 'authorization') continue;
    const match = /^Basic\s+(\S+)$/i.exec(value);
    if (!match) continue;
    out.push(match[1]);
    const decoded = Buffer.from(match[1], 'base64').toString();
    const colon = decoded.indexOf(':');
    if (colon >= 0 && colon < decoded.length - 1) {
      out.push(decoded.slice(colon + 1));
    }
  }
  return out;
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
  const draft: ITokenRequestDraft =
    auth.mtlsEndpoint === undefined
      ? {
          endpoint: grant.endpoint,
          clientId: grant.clientId,
          grantType: grant.grantType,
        }
      : {
          endpoint: grant.endpoint,
          mtlsEndpoint: auth.mtlsEndpoint,
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
 * sites read and nothing else: `message`, `code`, `status`, and a response of
 * `status`, `statusText`, empty `headers` and `data` reduced to the OAuth
 * error fields with every known secret redacted (`oauthErrorFields`): a server
 * may echo the request, or put a token there. No `config`, `request` or
 * `cause` is set, so `toJSON()`, which reads `this.config`, serialises none.
 */
function withoutRequest(
  error: unknown,
  secrets: readonly (string | undefined)[],
): unknown {
  if (!error || typeof error !== 'object') return error;
  const raw = error as Record<string, unknown>;
  if (!('config' in raw) && !('request' in raw) && !('response' in raw)) {
    return error;
  }
  const message =
    typeof raw.message === 'string' ? raw.message : 'the token request failed';
  const code = typeof raw.code === 'string' ? raw.code : undefined;
  const response = raw.response as Record<string, unknown> | undefined;
  const reduced =
    response && typeof response === 'object'
      ? ({
          status: response.status,
          statusText: response.statusText,
          headers: {},
          data: oauthErrorFields(response.data, secrets),
        } as unknown as AxiosResponse)
      : undefined;
  const failure = new AxiosError(message, code, undefined, undefined, reduced);
  if (failure.status === undefined && typeof raw.status === 'number') {
    failure.status = raw.status;
  }
  return failure;
}

/**
 * Sends one request — the prepared one when a strategy was given, else the
 * site's own `asToday` — and on failure throws it without the request
 * (`withoutRequest`). The request itself is not changed on either path.
 *
 * @param sent the secrets the site itself put in the request (a refresh
 *   token, a code, an assertion, a client secret); with what the strategy
 *   added, they are redacted from the error body that stays on the error.
 */
export async function sendTokenRequest<T>(
  prepared: PreparedTokenRequest | undefined,
  asToday: () => Promise<AxiosResponse<T>>,
  sent: readonly (string | undefined)[] = [],
): Promise<AxiosResponse<T>> {
  try {
    return prepared ? await axios<T>(prepared.config) : await asToday();
  } catch (error) {
    throw withoutRequest(error, [...sent, ...(prepared?.secrets ?? [])]);
  }
}
