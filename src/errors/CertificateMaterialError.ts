import { TOKEN_PROVIDER_ERROR_CODES } from '@mcp-abap-adt/interfaces-auth';
import { readSafely } from '../auth/knownCodes';
import { TokenProviderError } from './TokenProviderErrors';

// Every word object here is frozen: `words` hands it to anyone holding an
// error, and the refusal and the constructor read the same object.

/** The fixed words for certificate material that is not whole: the one source. */
export const CERTIFICATE_INCOMPLETE = Object.freeze({
  reason: 'the client certificate is incomplete',
  hint: 'give a PFX, or a certificate together with its key',
} as const);

/** The fixed words for certificate material that is whole but cannot be used. */
export const CERTIFICATE_UNUSABLE = Object.freeze({
  reason: 'the client certificate could not be used',
  hint: 'check the certificate, the key and the passphrase, and that a PFX uses current encryption (not legacy RC2)',
} as const);

/**
 * The fixed words for a client certificate past its `notAfter` — at pin time,
 * or before a request that would present it.
 */
export const CERTIFICATE_EXPIRED = Object.freeze({
  reason: 'the client certificate has expired',
  hint: 'renew the certificate; a token provider pins its certificate for life, so give the renewed one to a new provider',
} as const);

/**
 * Which fixed words a CertificateMaterialError carries. Internal: the package
 * index does not export it.
 */
export function certificateWords(incomplete: boolean, expired: boolean) {
  if (incomplete) return CERTIFICATE_INCOMPLETE;
  return expired ? CERTIFICATE_EXPIRED : CERTIFICATE_UNUSABLE;
}

/**
 * Thrown when certificate material cannot be used. Its message is fixed and
 * carries nothing of the material; a refusal is built from `incomplete` and
 * `expired` alone.
 */
export class CertificateMaterialError extends TokenProviderError {
  public readonly incomplete: boolean;
  /** Whole and usable, but past its `notAfter`. */
  public readonly expired: boolean;

  constructor(incomplete: boolean, expired = false) {
    super(
      certificateWords(incomplete === true, expired === true).reason,
      TOKEN_PROVIDER_ERROR_CODES.CERTIFICATE_MATERIAL_ERROR,
    );
    this.incomplete = incomplete === true;
    this.expired = expired === true;
    this.name = 'CertificateMaterialError';
    Object.setPrototypeOf(this, CertificateMaterialError.prototype);
  }

  /**
   * The fixed reason and hint this error stands for.
   *
   * @deprecated Use `refusalWords(error, what)`: this package never reads
   * `words` from a thrown value, since any object can carry its own.
   */
  get words(): { readonly reason: string; readonly hint: string } {
    return certificateWords(this.incomplete === true, this.expired === true);
  }
}

/**
 * The fixed words of a thrown CertificateMaterialError, chosen from its two
 * flags — never read from its `words`, which a forged object can carry — or
 * undefined when the value is not one. Total: an `instanceof` that throws is
 * "not one", and a flag that throws reads as not set.
 */
export function certificateWordsOf(
  error: unknown,
): { readonly reason: string; readonly hint: string } | undefined {
  try {
    if (!(error instanceof CertificateMaterialError)) return undefined;
  } catch {
    return undefined;
  }
  return certificateWords(
    readSafely(error, 'incomplete') === true,
    readSafely(error, 'expired') === true,
  );
}
