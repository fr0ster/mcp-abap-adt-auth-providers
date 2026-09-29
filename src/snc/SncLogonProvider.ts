/**
 * Passwordless RFC logon through an installed SNC product. The SNC library
 * authenticates during the RFC logon itself; this provider finds it (through
 * the locator it is given), checks the product when a probe applies, and hands
 * the wire the logon parameters. It opens no connection and loads no SAP
 * library. No collaborator is defaulted: forSecureLoginClient is the recipe.
 */

import type {
  AuthOutcome,
  IAuthProvider,
  IAuthRejection,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { OK, oops, safely } from '../auth/refusal';
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
import { sncRefusal } from './sncRefusal';

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
  /** Product checks; `[]` for none. Required. */
  probes: ISncProductProbe[];
  logger?: ILogger;
}

const detail = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

export class SncLogonProvider implements IAuthProvider {
  readonly kind = 'snc';
  private readonly partnerName: string;
  private readonly qop: string;
  private readonly myName?: string;
  private readonly locator: ISncLibraryLocator;
  private readonly probes: ISncProductProbe[];
  private readonly logger?: ILogger;
  private library?: SncLibrary;
  private product?: string;

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

  async prepare(): Promise<AuthOutcome> {
    let library: SncLibrary;
    try {
      library = await this.locator.locate();
    } catch (error) {
      this.logger?.warn(`SNC library not found: ${detail(error)}`);
      return oops(
        'no usable SNC library was found',
        'set sncLib to the SNC (GSS) library of your SNC product; the log lists every candidate tried',
      );
    }
    let product: string | undefined;
    for (const probe of this.probes) {
      try {
        if (!(await probe.appliesTo(library.path))) continue;
        await probe.check();
        product = probe.product;
        break;
      } catch (error) {
        this.logger?.warn(`${probe.product} check failed: ${detail(error)}`);
        return oops(
          `the ${probe.product} is not running or could not be checked`,
          `Start the ${probe.product} and log on to the profile used for SAP applications`,
        );
      }
    }
    this.library = library;
    this.product = product;
    this.logger?.debug(
      `SNC library ${library.path} (${library.archs.join('/')})${product ? `, ${product} running` : ', no product check'}`,
    );
    return OK;
  }

  /** No other way in: the wire's answer is this provider's own. */
  async establish(logon: ILogonTarget): Promise<AuthOutcome> {
    const library = this.library;
    if (!library)
      return oops(
        'the SNC provider is not prepared',
        'connect() prepares it first',
      );
    return safely('handing over the SNC logon parameters', () => {
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
    return OK;
  }

  async rejected(rejection: IAuthRejection): Promise<AuthOutcome> {
    return safely('explaining the SNC refusal', () => ({
      ok: false,
      refusal: sncRefusal(rejection.error, {
        library: this.library,
        product: this.product,
      }),
    }));
  }
}
