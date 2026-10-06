/**
 * Passwordless RFC logon through an installed SNC product. The SNC library
 * authenticates during the RFC logon itself; this provider finds it (through
 * the locator it is given), notes which product probe applies to it — the
 * product is named, never checked — and hands the wire the logon parameters.
 * It opens no connection and loads no SAP library. No collaborator is
 * defaulted: forSecureLoginClient is the recipe.
 *
 * Its four moments run inside `AuthProviderBase`'s boundary (spec §8.1):
 * anything that escapes a body is `unknown` with the moment's SNC operation —
 * "the SNC provider failed while resolving the SNC library (unknown error)"
 * (G10). Every refusal is minted (spec A.7); a library path is a diagnostic,
 * never a word (L9).
 */

import {
  authError,
  createParties,
  isSncQop,
  logFields,
  readFailure,
  relayOutcome,
} from '@mcp-abap-adt/auth-errors';
import type {
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { AuthProviderBase } from '../auth/AuthProviderBase';
import { throwIfAborted } from '../auth/attempt';
import { misconfigured } from '../auth/configuration';
import type { AnyOutcome } from '../auth/contractTransition';
import { readSafely } from '../auth/knownCodes';
import { OK } from '../auth/refusal';
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
import { foreignLocatorRefusal, sncCause, sncRefusal } from './sncRefusal';

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
   * The first attached party (spec §6b), as `attach(signal)` right after
   * construction. `prepare()` hands the locator and the probes a signal that
   * aborts when every attached party has aborted — the registry query is
   * killed then; with none live, `prepare()` waits for the machine. No
   * timeout of this package's choosing.
   */
  signal?: AbortSignal | undefined;
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
  /** The shipped Secure Login Client probe applies — the one product a refusal may name. */
  private secureLoginClient = false;

  constructor(config: SncLogonProviderConfig) {
    super({
      prepare: 'resolving-snc-library',
      establish: 'handing-over-snc-parameters',
      authorize: 'authorizing-snc-request',
      rejected: 'explaining-snc-refusal',
    });
    const given = readSafely(config, 'partnerName');
    const partnerName = typeof given === 'string' ? given.trim() : '';
    if (!partnerName) {
      // E20.
      throw misconfigured(
        authError.configuration({
          case: 'snc-partner-name-missing',
          fields: ['partnerName'],
        }),
      );
    }
    const qop = config.qop ?? '9';
    if (!isSncQop(qop)) {
      // E21: the value is never echoed (L5); `allowed` names the set.
      throw misconfigured(
        authError.configuration({
          case: 'snc-qop-invalid',
          fields: ['qop'],
          allowed: 'snc-qop',
        }),
      );
    }
    this.partnerName = partnerName;
    this.qop = qop;
    this.myName = config.myName?.trim() || undefined;
    this.locator = config.locator;
    this.probes = config.probes;
    this.logger = config.logger;
    // The config's signal is the first party; an aborted one adds nothing.
    if (config.signal !== undefined) this.parties.attach(config.signal);
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
    const system = nodeSncSystem();
    return new SncLogonProvider({
      partnerName: options.partnerName,
      qop: options.qop,
      myName: options.myName,
      logger: options.logger,
      signal: options.signal,
      locator: new DefaultSncLibraryLocator(system, options.sncLib),
      probes: [new SecureLoginClientProbe(system)],
    });
  }

  /**
   * Attaches a party sharing this provider (spec §6b): `prepare()` waits on
   * the parties live at its start and any attached while it runs, and ends
   * `aborted` when all of them have aborted. Released when its signal aborts
   * or by the returned `detach()`.
   */
  attach(signal: AbortSignal): () => void {
    return this.parties.attach(signal);
  }

  /** Resolve the library; note which probe applies. The product is not checked. */
  protected async onPrepare(): Promise<AnyOutcome> {
    const waiter = this.parties.waiterSignal();
    try {
      return await this.resolve(waiter?.signal);
    } finally {
      waiter?.release();
    }
  }

  private async resolve(signal: AbortSignal | undefined): Promise<AnyOutcome> {
    let found: SncLibrary;
    try {
      found = await this.locator.locate(signal);
    } catch (error) {
      throwIfAborted(signal);
      // G5–G7 only from the shipped locator (the approved source of the
      // paths); anything else a locator throws is G4's fixed sentence.
      const refusal = isShippedLocatorFailure(error)
        ? readFailure(error, 'resolving-snc-library')
        : foreignLocatorRefusal();
      // H4: the words; the paths only as the diagnostics field.
      const fields = logFields(refusal);
      logQuietly(() =>
        this.logger?.warn(`SNC library not found: ${fields.error}`, fields),
      );
      return { ok: false, refusal };
    }
    throwIfAborted(signal);
    // A getter that throws here is the boundary's (G10), as in 5.4.2.
    const given: unknown = found?.path;
    const path = typeof given === 'string' ? given.trim() : '';
    if (!path) {
      // G8. Built apart: a union as the contextual type widens the problem.
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
        if (await probe.appliesTo(library.path, signal)) {
          applying = probe;
          break;
        }
      } catch (error) {
        // H5: a probe that cannot tell names nothing; the logon goes on.
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
    this.library = library;
    this.secureLoginClient = applying instanceof SecureLoginClientProbe;
    logQuietly(() =>
      this.logger?.debug(
        `SNC library ${library.path} (${library.archs.join('/') || 'architecture not given'})${
          applying ? `, product: ${applying.product}` : ', no product named'
        }`,
      ),
    );
    return OK;
  }

  /** No other way in (rule 4): the wire's answer is this provider's own. */
  protected onEstablish(logon: ILogonTarget): AnyOutcome {
    const library = this.library;
    if (!library) {
      // G9.
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

  protected onAuthorize(_request: IRequestTarget): AnyOutcome {
    return OK;
  }

  /**
   * A GSS code in the error is explained first — the SDK reports SNC logon
   * failures as a communication failure. Without one, a status or an RFC key
   * that is not about the credential gets the neutral words (rule 5).
   */
  protected onRejected(rejection: IAuthRejection): AnyOutcome {
    const context = {
      library: this.library,
      secureLoginClient: this.secureLoginClient,
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
