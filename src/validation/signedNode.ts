/**
 * Which element the signature covers.
 *
 * Not "is there a valid signature" — that question has a true answer in a
 * document built for a wrapping attack, where a genuinely signed fragment sits
 * beside a forged one. The caller must read the element this returns and no
 * other.
 */

import { X509Certificate } from 'node:crypto';
import type { Document, Element, Node as XmlNode } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';

const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

/**
 * PEM in, PEM out; bare base64 DER gets its armour — and the result is proved
 * to be a certificate before anything uses it.
 *
 * The spec promises `idpCertificates` accepts either, and a consumer copying
 * `<X509Certificate>` out of identity-provider metadata has bare base64 DER in
 * their hand — the armour is not in the metadata. `xml-crypto` accepts only
 * PEM or a Buffer: measured, a bare base64 certificate makes OpenSSL throw
 * `DECODER routines::unsupported`, while the same bytes re-armoured verify.
 *
 * Left unnormalised that throw would be swallowed by the verification loop and
 * reported as "the signature does not verify against any configured
 * certificate" — blaming the assertion for the consumer's formatting.
 *
 * Base64 syntax alone does not make a string a certificate: `"AAAA"` passes
 * the character class, armours cleanly, and fails only inside OpenSSL, which
 * lands back at the same misleading message. So the armoured result is parsed
 * with `node:crypto`'s `X509Certificate`, which rejects `"AAAA"` with
 * `asn1 encoding routines::wrong tag` — measured, not assumed. Called once per
 * certificate at construction, so the cost never falls on a login.
 */
export function toPem(certificate: string): string {
  const trimmed = certificate.trim();
  const pem = trimmed.includes('-----BEGIN')
    ? trimmed
    : (() => {
        const body = trimmed.replace(/\s+/g, '');
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) {
          throw new Error(
            'a configured certificate is neither PEM nor base64 DER',
          );
        }
        const wrapped = body.replace(/(.{64})/g, '$1\n').trim();
        return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
      })();

  try {
    new X509Certificate(pem);
  } catch (error) {
    throw new Error(
      `a configured certificate is not a valid X.509 certificate: ${(error as Error).message}`,
    );
  }
  return pem;
}

/**
 * A value taken from the document before any signature has been verified,
 * made safe to put in a message: JSON-quoted, so a newline smuggled in as
 * `&#10;` shows as `\n` rather than forging a line in a log, and cut to 64
 * characters, so an attacker cannot fill a log with it.
 */
export function quoteUntrusted(value: string): string {
  const limit = 64;
  return JSON.stringify(
    value.length > limit ? `${value.slice(0, limit)}…` : value,
  );
}

/**
 * Verifies every signature in the document against the certificates and
 * returns the elements they reference. Throws when there is no signature, or
 * when any one of them fails a rule below.
 *
 * `doc` must be the parse of `xml`, and nothing else: signatures are found and
 * their references resolved in `doc`, while `xml-crypto` verifies the digests
 * over `xml`. Handed a `doc` from different bytes, the element returned would
 * not be the one whose bytes were verified.
 *
 * Several signatures are normal — identity providers often sign the Response
 * and the Assertion both. Each is held to every rule on its own; the caller
 * then takes the element it requires from the returned list.
 */
export function resolveSignedElements(
  xml: string,
  doc: Document,
  certificates: readonly string[],
): Element[] {
  const signatures = doc.getElementsByTagNameNS(DSIG_NS, 'Signature');
  if (signatures.length === 0) {
    throw new Error('the document carries no signature');
  }
  // Every signature is held to every rule: an extra signature that fails is
  // something that should not be there, not noise to skip. Two verifying
  // signatures over one element cannot occur — under the enveloped-signature
  // transform the later one changes the bytes the earlier one's digest
  // covered — so no separate rule guards against it.
  const covered: Element[] = [];
  for (let i = 0; i < signatures.length; i++) {
    covered.push(resolveOne(xml, doc, signatures[i], certificates));
  }
  return covered;
}

/** One signature: verified, exactly one reference, enveloped by its target. */
function resolveOne(
  xml: string,
  doc: Document,
  signatureNode: Element,
  certificates: readonly string[],
): Element {
  let verified = false;
  for (const certificate of certificates) {
    // Already normalised and proved at construction, so a throw here really
    // is a bad signature rather than a formatting mistake.
    // getCertFromKeyInfo is pinned to "none": a certificate the document
    // carries in its own KeyInfo is the sender's claim about who signed it,
    // and xml-crypto prefers it to publicCert when the hook returns one. It
    // defaults to a no-op in 6.x; stating it keeps a future default from
    // quietly letting an attacker's embedded certificate verify their own
    // signature.
    const verifier = new SignedXml({
      publicCert: certificate,
      getCertFromKeyInfo: () => null,
    });
    verifier.loadSignature(signatureNode as unknown as XmlNode);
    try {
      // Returns false for a digest mismatch and throws when the signature
      // value itself fails. Both mean "not this certificate".
      if (verifier.checkSignature(xml)) {
        verified = true;
        break;
      }
    } catch {
      // Try the next certificate in the rotation list.
    }
  }
  if (!verified) {
    throw new Error(
      'the signature does not verify against any configured certificate',
    );
  }

  // The signature is valid; now find what it actually covers. Exactly one
  // reference: two would be two candidate answers to "what is signed", the
  // ambiguity this module exists to remove.
  const references = signatureNode.getElementsByTagNameNS(DSIG_NS, 'Reference');
  if (references.length === 0) {
    throw new Error('the signature carries no ds:Reference');
  }
  if (references.length > 1) {
    throw new Error(
      `the signature carries ${references.length} ds:Reference; exactly one is allowed`,
    );
  }
  const uri = references[0].getAttribute('URI') ?? '';
  let referenced: Element | null = null;

  if (uri === '') {
    // An empty URI signs the whole document. It must still satisfy the
    // enveloping rule below — returning early here is exactly how a detached
    // signature with an empty reference walks straight past that rule.
    referenced = doc.documentElement as unknown as Element;
  } else if (!uri.startsWith('#')) {
    throw new Error(
      `the signature reference is not a same-document URI: ${quoteUntrusted(uri)}`,
    );
  } else {
    const id = uri.slice(1);
    const elements = doc.getElementsByTagName('*');
    for (let i = 0; i < elements.length; i++) {
      if (elements[i].getAttribute('ID') === id) {
        referenced = elements[i] as unknown as Element;
        break;
      }
    }
  }

  if (!referenced) {
    throw new Error(
      `the signature references ${quoteUntrusted(uri)}, which is not in the document`,
    );
  }

  // The enveloped signature must sit inside the element it references. A
  // signature moved elsewhere stays cryptographically valid over the bytes it
  // covers, so the maths alone will not catch it — this comparison is what
  // does. It is the check @node-saml/node-saml makes, and the one whose
  // absence made every response @mcp-abap-adt/auth-mocks produced
  // unacceptable to a real library until it was fixed there.
  if ((signatureNode.parentNode as unknown as Element | null) !== referenced) {
    throw new Error(
      'the signature is not inside the element it references, so it does not envelope it',
    );
  }

  return referenced;
}
