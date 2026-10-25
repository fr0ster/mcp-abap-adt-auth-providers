import type {
  INegotiateTokenSource,
  NegotiateSourceProblem,
  NegotiateTokenAnswer,
  NegotiateTokenOptions,
} from '@mcp-abap-adt/interfaces-auth';
import { mapGssFailure } from './gssProblem';

/** Which GSS mechanism the token is built for — the service's choice, no default. */
export type GssapiMechanism = 'spnego' | 'kerberos';

export interface GssapiTokenSourceOptions {
  /**
   * `spnego`: an SPNEGO token (RFC 4559, what `Negotiate` names), the binding's
   * `GSS_MECH_OID_SPNEGO`. `kerberos`: a bare Kerberos token,
   * `GSS_MECH_OID_KRB5`, for a service that takes one.
   */
  readonly mechanism: GssapiMechanism;
}

/** The part of the `kerberos` module this source uses. */
interface KerberosBinding {
  readonly GSS_MECH_OID_SPNEGO: number;
  readonly GSS_MECH_OID_KRB5: number;
  initializeClient(
    service: string,
    options: { mechOID: number },
  ): Promise<{ step(challenge: string): Promise<unknown> }>;
}

const OPTION_KEYS: ReadonlySet<string> = new Set(['mechanism']);

/** The binding, once loaded; a failed load is tried again on the next call. */
let loaded: KerberosBinding | undefined;

async function loadBinding(): Promise<KerberosBinding | undefined> {
  if (loaded) return loaded;
  try {
    const mod: unknown = await import('kerberos');
    const binding = mod as Partial<KerberosBinding>;
    if (
      typeof binding.initializeClient !== 'function' ||
      typeof binding.GSS_MECH_OID_SPNEGO !== 'number' ||
      typeof binding.GSS_MECH_OID_KRB5 !== 'number'
    )
      return undefined;
    loaded = binding as KerberosBinding;
    return loaded;
  } catch {
    return undefined;
  }
}

/**
 * Reads the options as own data: an accessor is never run, an unreadable
 * object (a throwing Proxy) is refused. A refusal is a `RangeError` naming
 * the option only, never its value — a programming error at composition,
 * before any moment.
 */
function readMechanism(options: unknown): GssapiMechanism {
  let keys: Array<string | symbol>;
  let descriptor: PropertyDescriptor | undefined;
  try {
    if (options === null || typeof options !== 'object')
      throw new RangeError('gssapiTokenSource: option "mechanism" is required');
    keys = Reflect.ownKeys(options);
    descriptor = Object.getOwnPropertyDescriptor(options, 'mechanism');
  } catch (error) {
    if (error instanceof RangeError) throw error;
    throw new RangeError('gssapiTokenSource: the options could not be read');
  }
  for (const key of keys) {
    if (typeof key === 'symbol')
      throw new RangeError('gssapiTokenSource: unknown option (a symbol key)');
    if (!OPTION_KEYS.has(key))
      throw new RangeError(`gssapiTokenSource: unknown option "${key}"`);
  }
  const value: unknown =
    descriptor && 'value' in descriptor ? descriptor.value : undefined;
  if (value !== 'spnego' && value !== 'kerberos')
    throw new RangeError(
      "gssapiTokenSource: option \"mechanism\" must be 'spnego' or 'kerberos'",
    );
  return value;
}

/**
 * The binding's form of the GSS host-based name `service@host`: as it is for
 * GSS-API (Linux, macOS); `service/host` for SSPI (Windows), which takes an
 * SPN.
 */
function bindingServiceName(servicePrincipal: string): string {
  if (process.platform !== 'win32') return servicePrincipal;
  const at = servicePrincipal.indexOf('@');
  return at < 0
    ? servicePrincipal
    : `${servicePrincipal.slice(0, at)}/${servicePrincipal.slice(at + 1)}`;
}

/** One new client, one `step('')`: its token, or the binding's failure as a problem. */
async function firstToken(
  binding: KerberosBinding,
  mechanism: GssapiMechanism,
  servicePrincipal: string,
): Promise<string | { problem: NegotiateSourceProblem }> {
  try {
    const mechOID =
      mechanism === 'spnego'
        ? binding.GSS_MECH_OID_SPNEGO
        : binding.GSS_MECH_OID_KRB5;
    const client = await binding.initializeClient(
      bindingServiceName(servicePrincipal),
      {
        mechOID,
      },
    );
    const token: unknown = await client.step('');
    return typeof token === 'string' ? token : { problem: 'source-failed' };
  } catch (error) {
    return { problem: mapGssFailure(error) };
  }
}

function refused(problem: NegotiateSourceProblem): NegotiateTokenAnswer {
  return Object.freeze({ ok: false, problem });
}

function aborted(options: NegotiateTokenOptions | undefined): boolean {
  const signal = options?.signal;
  return signal !== undefined && signal !== null && signal.aborted === true;
}

/**
 * A negotiate token source over the system's GSS-API (SSPI on Windows), through
 * the `kerberos` binding: each call builds a new client for the service
 * principal, takes its first token and keeps nothing. The identity is the
 * default one of the process's ticket cache (`KRB5CCNAME`, or the domain
 * logon); there is no principal option.
 */
export function gssapiTokenSource(
  options: GssapiTokenSourceOptions,
): INegotiateTokenSource {
  const mechanism = readMechanism(options);
  return {
    async token(servicePrincipal, tokenOptions) {
      try {
        if (typeof servicePrincipal !== 'string')
          return refused('source-failed');
        if (aborted(tokenOptions)) return refused('source-failed');
        const binding = await loadBinding();
        if (!binding) return refused('binding-unavailable');
        const token = await firstToken(binding, mechanism, servicePrincipal);
        // The binding cannot be cancelled: an abort during the call is
        // answered once it returns, and its token dropped.
        if (aborted(tokenOptions)) return refused('source-failed');
        if (typeof token !== 'string') return refused(token.problem);
        return Object.freeze({ ok: true, token });
      } catch {
        return refused('source-failed');
      }
    },
  };
}
