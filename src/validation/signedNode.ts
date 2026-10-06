/**
 * Which element the signature covers.
 *
 * Not "is there a valid signature" — that question has a true answer in a
 * document built for a wrapping attack, where a genuinely signed fragment sits
 * beside a forged one. The caller must read the element this returns and no
 * other.
 */

import { X509Certificate } from 'node:crypto';
import { authError } from '@mcp-abap-adt/auth-errors';
import type { Document, Element } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { refuse, several } from './samlRefusal';

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
        const body = withoutWhitespace(trimmed);
        if (!isBase64(body)) {
          throw new Error(
            'a configured certificate is neither PEM nor base64 DER',
          );
        }
        return `-----BEGIN CERTIFICATE-----\n${linesOf64(body)}\n-----END CERTIFICATE-----\n`;
      })();

  try {
    new X509Certificate(pem);
  } catch (error) {
    // Fixed words: OpenSSL's text is not this package's to repeat, and
    // whoever catches this logs the message. The original is the cause.
    throw new Error(
      'a configured certificate is not a valid X.509 certificate',
      {
        cause: error,
      },
    );
  }
  return pem;
}

/** Whitespace as `\\s` matched it: removed, every other character kept. */
function withoutWhitespace(value: string): string {
  let out = '';
  for (const char of value) {
    if (char.trim() !== '') out += char;
  }
  return out;
}

/** The base64 alphabet, at least one character, then at most two `=`. */
function isBase64(value: string): boolean {
  let end = value.length;
  let padding = 0;
  while (end > 0 && value[end - 1] === '=' && padding < 2) {
    end -= 1;
    padding += 1;
  }
  if (end === 0) return false;
  for (let i = 0; i < end; i += 1) {
    const c = value.charCodeAt(i);
    const ok =
      (c >= 0x41 && c <= 0x5a) || // A-Z
      (c >= 0x61 && c <= 0x7a) || // a-z
      (c >= 0x30 && c <= 0x39) || // 0-9
      c === 0x2b || // +
      c === 0x2f; // /
    if (!ok) return false;
  }
  return true;
}

/** The body cut into lines of 64 characters, PEM's armour. */
function linesOf64(body: string): string {
  const lines: string[] = [];
  for (let i = 0; i < body.length; i += 64) lines.push(body.slice(i, i + 64));
  return lines.join('\n');
}

/**
 * Verifies every signature in the document against the certificates and
 * returns the elements they reference. Throws an `AuthProviderFailure` of
 * `saml-assertion` naming the rule when there is no signature, or when any
 * one of them fails a rule below.
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
    refuse(
      authError['saml-assertion']({ rule: 'no-signature', check: 'signature' }),
    );
  }
  // Every signature is held to every rule: an extra signature that fails is
  // something that should not be there, not noise to skip. Two verifying
  // signatures over one element cannot occur — under the enveloped-signature
  // transform the later one changes the bytes the earlier one's digest
  // covered — so no separate rule guards against it.
  const covered: Element[] = [];
  for (const signature of signatures) {
    covered.push(resolveOne(xml, doc, signature, certificates));
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
    // loadSignature throws for a malformed Signature. xml-crypto's message
    // embeds the offending element — document text — and reaches nothing
    // (L7): the rule says what failed.
    try {
      verifier.loadSignature(signatureNode);
    } catch {
      refuse(
        authError['saml-assertion']({
          rule: 'signature-malformed',
          check: 'signature',
        }),
      );
    }
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
    refuse(
      authError['saml-assertion']({
        rule: 'signature-not-verified',
        check: 'signature',
      }),
    );
  }

  // The signature is valid; now find what it actually covers. Exactly one
  // reference: two would be two candidate answers to "what is signed", the
  // ambiguity this module exists to remove.
  const references = signatureNode.getElementsByTagNameNS(DSIG_NS, 'Reference');
  const reference = references.item(0);
  if (!reference) {
    return refuse(
      authError['saml-assertion']({ rule: 'no-reference', check: 'signature' }),
    );
  }
  if (references.length > 1) {
    refuse(
      authError['saml-assertion']({
        rule: 'several-references',
        check: 'signature',
        ...several(references.length),
      }),
    );
  }
  const uri = reference.getAttribute('URI') ?? '';
  let referenced: Element | null = null;

  if (uri === '') {
    // An empty URI signs the whole document. It must still satisfy the
    // enveloping rule below — returning early here is exactly how a detached
    // signature with an empty reference walks straight past that rule.
    referenced = doc.documentElement;
  } else if (!uri.startsWith('#')) {
    refuse(
      authError['saml-assertion'](
        { rule: 'reference-not-same-document', check: 'signature' },
        { referenceUri: uri },
      ),
    );
  } else {
    const id = uri.slice(1);
    const elements = doc.getElementsByTagName('*');
    for (const element of elements) {
      if (element.getAttribute('ID') === id) {
        referenced = element;
        break;
      }
    }
  }

  if (!referenced) {
    return refuse(
      authError['saml-assertion'](
        { rule: 'reference-not-found', check: 'signature' },
        { referenceUri: uri },
      ),
    );
  }

  // The enveloped signature must sit inside the element it references. A
  // signature moved elsewhere stays cryptographically valid over the bytes it
  // covers, so the maths alone will not catch it — this comparison is what
  // does. It is the check @node-saml/node-saml makes, and the one whose
  // absence made every response @mcp-abap-adt/auth-mocks produced
  // unacceptable to a real library until it was fixed there.
  if (signatureNode.parentNode !== referenced) {
    refuse(
      authError['saml-assertion']({
        rule: 'signature-not-enveloped',
        check: 'signature',
      }),
    );
  }

  return referenced;
}
