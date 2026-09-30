/**
 * Passwordless RFC logon through an installed SNC product. The SNC library
 * authenticates during the RFC logon itself; this provider finds it (through
 * the locator it is given), notes which product probe applies to it — the
 * product is named, never checked — and hands the wire the logon parameters.
 * It opens no connection and loads no SAP library. No collaborator is
 * defaulted: forSecureLoginClient is the recipe.
 */

import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { OK, oops } from '../auth/refusal';
import { readRejection } from '../auth/rejection';
import { ValidationError } from '../errors/TokenProviderErrors';
import {
  DefaultSncLibraryLocator,
  type ISncLibraryLocator,
  type SncLibrary,
} from './DefaultSncLibraryLocator';
import {
  type ISncProductProbe,
  SecureLoginClientProbe,
} from './SecureLoginClientProbe';
import { nodeSncSystem } from './SncSystem';
import { locateRefusal, sncCause, sncRefusal } from './sncRefusal';

/** SAP's SNC_QOP values: 1 authentication, 2 integrity, 3 privacy, 8 default, 9 maximum. */
const SNC_QOP_VALUES = ['1', '2', '3', '8', '9'];

export interface SncLogonProviderConfig {
  /** The system's SNC name, e.g. `p:CN=SID, O=ACME`. */
  partnerName: string;
  /** `'1' | '2' | '3' | '8' | '9'`; default `'9'` (maximum available). */
  qop?: string;
  /** Sent as `snc_myname` only when set. */
  myName?: string;
  /** Where the SNC library is. Required. */
  locator: ISncLibraryLocator;
  /** Which product is behind the library, for the `rejected` hint; `[]` for none. Required. */
  probes: ISncProductProbe[];
  logger?: ILogger;
}

const detail = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

/**
 * The outer boundary of every method (rule 1): the SNC wording inside stays,
 * and anything that still escapes — a throwing logger, a malformed
 * collaborator — is a fixed SNC Oops. Nothing is logged here: the logger may
 * be what threw.
 */
async function bounded(
  moment: string,
  work: () => AuthOutcome | Promise<AuthOutcome>,
): Promise<AuthOutcome> {
  try {
    return await work();
  } catch {
    return oops(`the SNC provider failed while ${moment} (unknown error)`);
  }
}

export class SncLogonProvider implements IAuthProvider {
  readonly kind = 'snc';
  private readonly partnerName: string;
  private readonly qop: string;
  private readonly myName?: string;
  private readonly locator: ISncLibraryLocator;
  private readonly probes: ISncProductProbe[];
  private readonly logger?: ILogger;
  private library?: SncLibrary;
  /** The shipped Secure Login Client probe applies — the one product a refusal may name. */
  private secureLoginClient = false;

  constructor(config: SncLogonProviderConfig) {
    const partnerName = config.partnerName?.trim();
    if (!partnerName) {
      throw new ValidationError(
        'SncLogonProvider needs partnerName — the system’s SNC name.',
        ['partnerName'],
      );
    }
    const qop = config.qop ?? '9';
    if (!SNC_QOP_VALUES.includes(qop)) {
      throw new ValidationError(
        `SncLogonProvider: qop must be one of ${SNC_QOP_VALUES.join(', ')}, got '${qop}'.`,
        ['qop'],
      );
    }
    this.partnerName = partnerName;
    this.qop = qop;
    this.myName = config.myName?.trim() || undefined;
    this.locator = config.locator;
    this.probes = config.probes;
    this.logger = config.logger;
  }

  /** The usual choice: this machine, library discovery, the Secure Login Client probe. */
  static forSecureLoginClient(options: {
    partnerName: string;
    qop?: string;
    sncLib?: string;
    myName?: string;
    logger?: ILogger;
  }): SncLogonProvider {
    const system = nodeSncSystem();
    return new SncLogonProvider({
      partnerName: options.partnerName,
      qop: options.qop,
      myName: options.myName,
      logger: options.logger,
      locator: new DefaultSncLibraryLocator(system, options.sncLib),
      probes: [new SecureLoginClientProbe(system)],
    });
  }

  /** Resolve the library; note which probe applies. The product is not checked. */
  async prepare(): Promise<AuthOutcome> {
    return bounded('resolving the SNC library', async () => {
      let found: SncLibrary;
      try {
        found = await this.locator.locate();
      } catch (error) {
        const refusal = locateRefusal(error);
        this.log('warn', `SNC library not found: ${detail(error)}`);
        return { ok: false, refusal };
      }
      const path = typeof found?.path === 'string' ? found.path.trim() : '';
      if (!path) {
        return oops(
          'no usable SNC library was found: the locator returned no path',
          'set sncLib to the SNC (GSS) library of your SNC product',
        );
      }
      const library: SncLibrary = {
        path,
        archs: Array.isArray(found.archs) ? found.archs : [],
      };
      let applying: ISncProductProbe | undefined;
      for (const probe of this.probes) {
        try {
          if (await probe.appliesTo(library.path)) {
            applying = probe;
            break;
          }
        } catch (error) {
          // A probe that cannot tell names nothing; the logon goes on.
          this.log('warn', `an SNC product probe failed: ${detail(error)}`);
        }
      }
      this.library = library;
      this.secureLoginClient = applying instanceof SecureLoginClientProbe;
      this.log(
        'debug',
        `SNC library ${library.path} (${library.archs.join('/') || 'architecture not given'})${
          applying ? `, product: ${applying.product}` : ', no product named'
        }`,
      );
      return OK;
    });
  }

  /** No other way in: the wire's answer is this provider's own. */
  async establish(logon: ILogonTarget): Promise<AuthOutcome> {
    return bounded('handing over the SNC logon parameters', () => {
      const library = this.library;
      if (!library)
        return oops(
          'the SNC provider is not prepared',
          'connect() prepares it first',
        );
      const params: Record<string, string> = {
        snc_mode: '1',
        snc_partnername: this.partnerName,
        snc_qop: this.qop,
        snc_lib: library.path,
      };
      if (this.myName) params.snc_myname = this.myName;
      return logon.logonParameters(params);
    });
  }

  async authorize(_request: IRequestTarget): Promise<AuthOutcome> {
    return bounded('authorizing a request', () => OK);
  }

  /**
   * A GSS code in the error is explained first — the SDK reports SNC logon
   * failures as a communication failure. Without one, a status or an RFC key
   * that is not about the credential gets the neutral words.
   */
  async rejected(rejection: IAuthRejection): Promise<AuthOutcome> {
    return bounded('explaining the SNC refusal', () => {
      const context = {
        library: this.library,
        secureLoginClient: this.secureLoginClient,
      };
      const cause = sncCause(rejection?.error, context);
      if (cause) return { ok: false, refusal: cause };
      const read = readRejection(rejection);
      if (read.verdict === 'not-credential') {
        return { ok: false, refusal: read.refusal };
      }
      return { ok: false, refusal: sncRefusal(rejection?.error, context) };
    });
  }

  /** A log line that cannot take the method down with it. */
  private log(level: 'warn' | 'debug', message: string): void {
    try {
      this.logger?.[level](message);
    } catch {
      // The log sink is down; the answer does not depend on it.
    }
  }
}
