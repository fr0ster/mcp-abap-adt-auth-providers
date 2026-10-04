import { createHash, X509Certificate } from 'node:crypto';
import { createSecureContext, TLSSocket } from 'node:tls';
import type {
  AuthOutcome,
  ICertificateMaterial,
} from '@mcp-abap-adt/interfaces-auth';
import {
  CERTIFICATE_INCOMPLETE,
  CERTIFICATE_UNUSABLE,
  CertificateMaterialError,
} from '../errors/CertificateMaterialError';
import { OK, oops } from './refusal';

function isIncomplete(material: ICertificateMaterial): boolean {
  // A TLS context accepts {}, a certificate alone or a key alone, and the
  // logon then goes out with no client certificate at all.
  return material.pfx === undefined && (!material.cert || !material.key);
}

/**
 * Proves certificate material whole and usable: complete first, then a TLS
 * context built from it. Throws a CertificateMaterialError (`incomplete` says
 * which) — its words are fixed; an error's own text never reaches them.
 */
export function assertCertificateMaterial(
  material: ICertificateMaterial,
): void {
  if (isIncomplete(material)) throw new CertificateMaterialError(true);
  try {
    createSecureContext(material);
  } catch {
    throw new CertificateMaterialError(false);
  }
}

/** The same proof as an outcome: the refusal carries the fixed words. */
export function checkCertificateMaterial(
  material: ICertificateMaterial,
): AuthOutcome {
  try {
    assertCertificateMaterial(material);
  } catch (e) {
    const words =
      e instanceof CertificateMaterialError && e.incomplete
        ? CERTIFICATE_INCOMPLETE
        : CERTIFICATE_UNUSABLE;
    return oops(words.reason, words.hint);
  }
  return OK;
}

/**
 * SHA-256 over the leaf certificate's DER, base64url without padding. The
 * leaf of a PEM chain is its first certificate. It expects material that
 * already passed `checkCertificateMaterial` and does not prove it usable (a
 * PEM whose key is not the certificate's still yields a thumbprint). It
 * throws a CertificateMaterialError when the material is incomplete or no
 * leaf certificate can be read from it.
 */
export function certificateThumbprint(material: ICertificateMaterial): string {
  if (isIncomplete(material)) throw new CertificateMaterialError(true);
  try {
    return createHash('sha256').update(leafDer(material)).digest('base64url');
  } catch {
    throw new CertificateMaterialError(false);
  }
}

function leafDer(material: ICertificateMaterial): Buffer {
  if (material.pfx !== undefined) {
    const socket = new TLSSocket(null as never, {
      secureContext: createSecureContext(material),
    });
    try {
      const leaf = socket.getCertificate() as { raw?: Buffer } | null;
      if (!leaf?.raw) throw new Error('no leaf');
      return leaf.raw;
    } finally {
      socket.destroy();
    }
  }
  if (!material.cert) throw new Error('no leaf');
  return new X509Certificate(material.cert).raw;
}
