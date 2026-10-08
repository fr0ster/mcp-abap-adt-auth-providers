/**
 * Passwordless RFC logon through an installed SNC product. The SNC library
 * authenticates during the RFC logon itself; this provider finds it (through
 * the locator it is given), notes which product probe applies to it — the
 * product is named, never checked — and hands the wire the logon parameters.
 * It opens no connection and loads no SAP library. No collaborator is
 * defaulted: forSecureLoginClient is the recipe.
 *
 * Its four moments run inside `AuthProviderBase`'s boundary: anything that
 * escapes a body is `unknown` with the moment's SNC operation — "the SNC
 * provider failed while resolving the SNC library (unknown error)". Every
 * refusal is minted; a library path is a diagnostic, never a word.
 */

import {
  authError,
  createParties,
  isSncQop,
  logFields,
  OK,
  readFailure,
  relayOutcome,
} from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { AuthProviderBase } from '../auth/AuthProviderBase';
import { throwIfAborted, untilAborted } from '../auth/attempt';
import { misconfigured, ownOptions } from '../auth/configuration';
import { readSafely } from '../auth/knownCodes';
import { readRejection } from '../auth/rejection';
import { logQuietly } from '../auth/tokenRequest';
import {
  DefaultSncLibraryLocator,
  type ISncLibraryLocator,
  isShippedLocatorFailure,
  type SncLibrary,
} from './DefaultSncLibraryLocator';
import {
  type ISncProductProbe,
  SecureLoginClientProbe,
} from './SecureLoginClientProbe';
import { nodeSncSystem } from './SncSystem';
import { SECURE_LOGIN_CLIENT } from './secureLoginClient';
import {
  archsOf,
  foreignLocatorRefusal,
  type GssRefusals,
  sncCause,
  sncRefusal,
} from './sncRefusal';

export interface SncLogonProviderConfig {
  /** The system's SNC name, e.g. `p:CN=SID, O=ACME`. */
  partnerName: string;
  /** `'1' | '2' | '3' | '8' | '9'`; default `'9'` (maximum available). */
  qop?: string | undefined;
  /** Sent as `snc_myname` only when set. */
  myName?: string | undefined;
  /** Where the SNC library is. Required. */
  locator: ISncLibraryLocator;
  /** Which product is behind the library, for the `rejected` hint; `[]` for none. Required. */
  probes: ISncProductProbe[];
  logger?: ILogger | undefined;
  /**
   * The first attached party, as `attach(signal)` right after
   * construction. `prepare()` hands the locator and the probes a signal that
   * aborts when every attached party has aborted — the registry query is
   * killed then; with none live, `prepare()` waits for the machine. No
   * timeout of this package's choosing.
   */
  signal?: AbortSignal | undefined;
}

/**
 * A configured field, read once as an own data property: an accessor (a
 * getter is never run), a Proxy trap that throws or a non-object config is
 * unreadable; an absent property reads as `undefined`.
 */
function ownData(
  object: unknown,
  key: string,
): { readable: true; value: unknown } | { readable: false } {
  if (object === null || typeof object !== 'object') {
    return { readable: false };
  }
  try {
    const descriptor = Object.getOwnPropertyDescriptor(object, key);
    if (descriptor === undefined) return { readable: true, value: undefined };
    return 'value' in descriptor
      ? { readable: true, value: descriptor.value }
      : { readable: false };
  } catch {
    return { readable: false };
  }
}

export class SncLogonProvider extends AuthProviderBase {
  readonly kind = 'snc';
  private readonly partnerName: string;
  private readonly qop: string;
  private readonly myName?: string | undefined;
  private readonly locator: ISncLibraryLocator;
  private readonly probes: ISncProductProbe[];
  private readonly logger?: ILogger | undefined;
  private readonly parties = createParties();
  private library?: SncLibrary | undefined;
  /** The GSS explanations carrying the library diagnostic, minted by `prepare()`. */
  private explained?: GssRefusals | undefined;
  /** The shipped Secure Login Client probe applies — the one product a refusal may name. */
  private secureLoginClient = false;

  constructor(config: SncLogonProviderConfig) {
    super({
      prepare: 'resolving-snc-library',
      establish: 'handing-over-snc-parameters',
      authorize: 'authorizing-snc-request',
      rejected: 'explaining-snc-refusal',
    });
    const given = ownData(config, 'partnerName');
    const partnerName =
      given.readable && typeof given.value === 'string'
        ? given.value.trim()
        : '';
    if (!partnerName) {
      throw misconfigured(
        authError.configuration({
          case: 'snc-partner-name-missing',
          fields: ['partnerName'],
        }),
      );
    }
    const qopRead = ownData(config, 'qop');
    const qop = qopRead.readable ? (qopRead.value ?? '9') : undefined;
    if (!isSncQop(qop)) {
      // The value is never echoed; `allowed` names the set.
      throw misconfigured(
        authError.configuration({
          case: 'snc-qop-invalid',
          fields: ['qop'],
          allowed: 'snc-qop',
        }),
      );
    }
    const myName = ownData(config, 'myName');
    if (
      !myName.readable ||
      (myName.value !== undefined && typeof myName.value !== 'string')
    ) {
      // No snc case names myName (interfaces-auth's CONFIG_CASES): the
      // generic case, naming the field — never the value or a getter's throw.
      throw misconfigured(
        authError.configuration({
          case: 'required-fields-missing',
          fields: ['myName'],
        }),
      );
    }
    this.partnerName = partnerName;
    this.qop = qop;
    this.myName =
      typeof myName.value === 'string'
        ? myName.value.trim() || undefined
        : undefined;
    // The collaborators, read once as own data: an accessor or a throwing
    // Proxy reads as absent, and an absent locator or probe list is used
    // only inside a moment, whose boundary answers it.
    const collaborators = ownOptions<Partial<SncLogonProviderConfig>>(config);
    this.locator = collaborators.locator as ISncLibraryLocator;
    this.probes = collaborators.probes as ISncProductProbe[];
    this.logger = collaborators.logger;
    // The config's signal is the first party; an aborted one adds nothing.
    if (collaborators.signal !== undefined) {
      this.parties.attach(collaborators.signal);
    }
  }

  /** The usual choice: this machine, library discovery, the Secure Login Client probe. */
  static forSecureLoginClient(options: {
    partnerName: string;
    qop?: string;
    sncLib?: string;
    myName?: string;
    logger?: ILogger;
    signal?: AbortSignal;
  }): SncLogonProvider {
    // Read once as own data, like every option: a hostile object throws
    // nothing of its own; the constructor refuses what is missing.
    const own = ownOptions<Partial<typeof options>>(options);
    const system = nodeSncSystem();
    return new SncLogonProvider({
      partnerName: own.partnerName as string,
      qop: own.qop,
      myName: own.myName,
      logger: own.logger,
      signal: own.signal,
      locator: new DefaultSncLibraryLocator(system, own.sncLib),
      probes: [new SecureLoginClientProbe(system)],
    });
  }

  /**
   * Attaches a party sharing this provider: `prepare()` waits on
   * the parties live at its start and any attached while it runs, and ends
   * `aborted` when all of them have aborted. Released when its signal aborts
   * or by the returned `detach()`.
   */
  attach(signal: AbortSignal): () => void {
    return this.parties.attach(signal);
  }

  /** Resolve the library; note which probe applies. The product is not checked. */
  protected async onPrepare(): Promise<AuthOutcome> {
    const waiter = this.parties.waiterSignal();
    try {
      return await this.resolve(waiter?.signal);
    } finally {
      waiter?.release();
    }
  }

  private async resolve(signal: AbortSignal | undefined): Promise<AuthOutcome> {
    let found: SncLibrary;
    try {
      // The locator is the consumer's: its answer — any promise, Bluebird
      // or Q included — is awaited as it is, and stops being waited for at
      // the parties' abort, whether or not it honours the signal.
      found = await untilAborted(
        Promise.resolve(this.locator.locate(signal)),
        signal,
      );
    } catch (error) {
      throwIfAborted(signal);
      // A library's failure words and paths come only from the shipped locator
      // (the approved source of the paths); anything else a locator throws is
      // one fixed sentence.
      const refusal = isShippedLocatorFailure(error)
        ? readFailure(error, 'resolving-snc-library')
        : foreignLocatorRefusal();
      // The words; the paths only as the diagnostics field.
      const fields = logFields(refusal);
      logQuietly(() =>
        this.logger?.warn(`SNC library not found: ${fields.error}`, fields),
      );
      return { ok: false, refusal };
    }
    throwIfAborted(signal);
    // A getter that throws here is the boundary's, as in 5.4.2.
    const given: unknown = found?.path;
    const path = typeof given === 'string' ? given.trim() : '';
    if (!path) {
      // Built apart: a union as the contextual type widens the problem.
      const refusal = authError.snc({ problem: 'locator-returned-no-path' });
      return { ok: false, refusal };
    }
    const archs: unknown = found.archs;
    const library: SncLibrary = {
      path,
      archs: Array.isArray(archs) ? archs : [],
    };
    let applying: ISncProductProbe | undefined;
    for (const probe of this.probes) {
      try {
        if (
          await untilAborted(
            Promise.resolve(probe.appliesTo(library.path, signal)),
            signal,
          )
        ) {
          applying = probe;
          break;
        }
      } catch (error) {
        // An abort is the consumer's, not the probe's failure: no line is
        // logged.
        throwIfAborted(signal);
        // A probe that cannot tell names nothing; the logon goes on.
        const fields = logFields(readFailure(error, 'probing-snc-product'));
        logQuietly(() =>
          this.logger?.warn(
            `an SNC product probe failed: ${fields.error}`,
            fields,
          ),
        );
      }
    }
    throwIfAborted(signal);
    const secureLoginClient = applying instanceof SecureLoginClientProbe;
    // The one extraction site of the `library` diagnostic: the
    // path the locator returned, trimmed here. `rejected()` relays these.
    const libraryArchs = archsOf(library);
    const withArchs = libraryArchs.length ? { libraryArchs } : {};
    const diagnostics = { library: library.path };
    const explained: GssRefusals = {
      noCredential: authError.snc(
        { problem: 'no-credential', secureLoginClient, ...withArchs },
        diagnostics,
      ),
      initFailed: authError.snc(
        { problem: 'library-init-failed', ...withArchs },
        diagnostics,
      ),
    };
    this.library = library;
    this.secureLoginClient = secureLoginClient;
    this.explained = explained;
    const admitted = explained.initFailed.diagnostics?.library;
    // Fixed words; only admitted values as fields — the path through
    // LocalPath, the architectures from the closed set, and a product name
    // only when it is the shipped probe's. A consumer's text never reaches
    // the line, so a newline or a bidi control cannot forge one.
    const fields = {
      library: typeof admitted === 'string' ? admitted : null,
      archs: libraryArchs,
      product: this.secureLoginClient
        ? SECURE_LOGIN_CLIENT
        : applying
          ? 'a consumer probe'
          : 'none',
    };
    logQuietly(() => this.logger?.debug('SNC library resolved', fields));
    return OK;
  }

  /** No other way in (rule 4): the wire's answer is this provider's own. */
  protected onEstablish(logon: ILogonTarget): AuthOutcome {
    const library = this.library;
    if (!library) {
      return {
        ok: false,
        refusal: authError['not-prepared']({ provider: 'snc' }),
      };
    }
    const params: Record<string, string> = {
      snc_mode: '1',
      snc_partnername: this.partnerName,
      snc_qop: this.qop,
      snc_lib: library.path,
    };
    if (this.myName) params.snc_myname = this.myName;
    // The target's answer, returned or thrown — never the target's object.
    return relayOutcome(
      () => logon.logonParameters(params),
      'logon-parameters',
      'handing-over-snc-parameters',
    ).outcome;
  }

  protected onAuthorize(_request: IRequestTarget): AuthOutcome {
    return OK;
  }

  /**
   * A GSS code in the error is explained first — the SDK reports SNC logon
   * failures as a communication failure. Without one, a status or an RFC key
   * that is not about the credential gets the neutral words (rule 5).
   */
  protected onRejected(rejection: IAuthRejection): AuthOutcome {
    const context = {
      secureLoginClient: this.secureLoginClient,
      explained: this.explained,
    };
    const error = readSafely(rejection, 'error');
    const cause = sncCause(error, context);
    if (cause) return { ok: false, refusal: cause };
    const read = readRejection(rejection);
    if (read.verdict === 'not-credential') {
      return { ok: false, refusal: read.refusal };
    }
    return { ok: false, refusal: sncRefusal(error, context) };
  }
}
