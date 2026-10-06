import { createHash, X509Certificate } from 'node:crypto';
import { createSecureContext, TLSSocket } from 'node:tls';
import {
  AuthProviderFailure,
  authError,
  classify,
  OK,
} from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  ClientCertificateProblem,
  ICertificateMaterial,
} from '@mcp-abap-adt/interfaces-auth';

/**
 * A4: certificate material that cannot be presented — `incomplete`,
 * `unusable` or `expired` — as a `client-certificate` failure. Its words are
 * fixed; nothing of the material, nor of an error a check threw, is kept.
 */
export function certificateFailure(
  problem: ClientCertificateProblem,
): AuthProviderFailure {
  return new AuthProviderFailure(authError['client-certificate']({ problem }));
}

function isIncomplete(material: ICertificateMaterial): boolean {
  // A TLS context accepts {}, a certificate alone or a key alone, and the
  // logon then goes out with no client certificate at all.
  return material.pfx === undefined && (!material.cert || !material.key);
}

/**
 * Proves certificate material whole, usable and current: complete first, then
 * a TLS context built from it, then its leaf certificate not past `notAfter`.
 * Throws a `client-certificate` failure (A4) whose `problem` says which —
 * its words are fixed; an error's own text never reaches them.
 */
export function assertCertificateMaterial(
  material: ICertificateMaterial,
): void {
  if (isIncomplete(material)) throw certificateFailure('incomplete');
  try {
    createSecureContext(material);
  } catch {
    throw certificateFailure('unusable');
  }
  assertNotExpired(certificateNotAfter(material));
}

/**
 * When the leaf certificate stops being valid: its `notAfter`, in epoch
 * milliseconds. Throws `client-certificate` `unusable` when no leaf can be
 * read (`incomplete` for material without one).
 */
export function certificateNotAfter(material: ICertificateMaterial): number {
  if (isIncomplete(material)) throw certificateFailure('incomplete');
  let notAfter: number;
  try {
    notAfter = Date.parse(new X509Certificate(leafDer(material)).validTo);
  } catch {
    throw certificateFailure('unusable');
  }
  if (!Number.isFinite(notAfter)) throw certificateFailure('unusable');
  return notAfter;
}

/** Throws `client-certificate` `expired` once `notAfter` is reached. */
export function assertNotExpired(notAfter: number): void {
  if (Date.now() >= notAfter) throw certificateFailure('expired');
}

/**
 * The same proof as an outcome (B14): the `client-certificate` error the
 * check threw. Reading the material may run a consumer's getter, which may
 * throw anything: `classify` answers a failure's own error, and anything
 * that is not a `client-certificate` error is `unusable`.
 */
export function checkCertificateMaterial(
  material: ICertificateMaterial,
): AuthOutcome {
  try {
    assertCertificateMaterial(material);
  } catch (e) {
    const error = classify(e, 'loading-certificate');
    return {
      ok: false,
      refusal:
        error.kind === 'client-certificate'
          ? error
          : authError['client-certificate']({ problem: 'unusable' }),
    };
  }
  return OK;
}

/**
 * SHA-256 over the leaf certificate's DER, base64url without padding. The
 * leaf of a PEM chain is its first certificate. It expects material that
 * already passed `checkCertificateMaterial` and does not prove it usable (a
 * PEM whose key is not the certificate's still yields a thumbprint). It
 * throws `client-certificate` `incomplete` or `unusable` when the material is
 * incomplete or no leaf certificate can be read from it.
 */
export function certificateThumbprint(material: ICertificateMaterial): string {
  if (isIncomplete(material)) throw certificateFailure('incomplete');
  try {
    return createHash('sha256').update(leafDer(material)).digest('base64url');
  } catch {
    throw certificateFailure('unusable');
  }
}

function leafDer(material: ICertificateMaterial): Buffer {
  if (material.pfx !== undefined) {
    const socket = new TLSSocket(null as never, {
      secureContext: createSecureContext(material),
    });
    try {
      const leaf = socket.getCertificate() as { raw?: Buffer } | null;
      if (!leaf?.raw) throw certificateFailure('unusable');
      return leaf.raw;
    } finally {
      socket.destroy();
    }
  }
  if (!material.cert) throw certificateFailure('incomplete');
  return new X509Certificate(material.cert).raw;
}
