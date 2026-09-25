import { describe, expect, it } from '@jest/globals';
import {
  generateKeyMaterial,
  type KeyMaterial,
  signXml,
} from '@mcp-abap-adt/auth-mocks';
import { DOMParser, type Document, type Element } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { resolveSignedElements, toPem } from '../../validation/signedNode';

const parse = (xml: string) =>
  new DOMParser().parseFromString(xml, 'text/xml') as unknown as Document;

const ASSERTION = (id = '_a1') =>
  `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}">` +
  `<saml:Issuer>mock-idp</saml:Issuer></saml:Assertion>`;

const RESPONSE = (inner: string, id = '_r1') =>
  `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="${id}">` +
  `${inner}</samlp:Response>`;

const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

/**
 * ASSERTION() signed by xml-crypto, with `patch` applied to the finished
 * Reference before SignatureValue is computed — so the signature over the
 * patched SignedInfo is genuine and only the rule under test can refuse it.
 * Editing a Reference after signing would break SignatureValue instead, and
 * the test would stop at "does not verify". `addAllReferences` is private in
 * xml-crypto's types, hence the cast; it builds SignedInfo's References and
 * runs before calculateSignatureValue in computeSignature (xml-crypto 6.3.2).
 */
function signWithPatchedReference(
  key: KeyMaterial,
  patch: (reference: Element, doc: Document) => void,
): string {
  const signer = new SignedXml({
    privateKey: key.privateKeyPem,
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
  });
  signer.addReference({
    xpath: "//*[local-name(.)='Assertion']",
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  const internals = signer as unknown as {
    addAllReferences: (
      doc: Document,
      signature: Element,
      ...rest: unknown[]
    ) => void;
  };
  const original = internals.addAllReferences.bind(signer);
  internals.addAllReferences = (doc, signature, ...rest) => {
    original(doc, signature, ...rest);
    patch(signature.getElementsByTagNameNS(DSIG_NS, 'Reference')[0], doc);
  };
  signer.computeSignature(ASSERTION(), {
    location: { reference: "//*[local-name(.)='Issuer']", action: 'after' },
  });
  return RESPONSE(signer.getSignedXml());
}

/** Whether xml-crypto itself accepts the document's only signature. */
function xmlCryptoVerifies(xml: string, key: KeyMaterial): boolean {
  const probe = new SignedXml({ publicCert: key.certificatePem });
  probe.loadSignature(
    parse(xml).getElementsByTagNameNS(DSIG_NS, 'Signature')[0] as never,
  );
  return probe.checkSignature(xml);
}

describe('resolveSignedElements', () => {
  it('returns the Assertion when the Assertion is signed', () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key);
    const wrapped = RESPONSE(signed);
    const [element] = resolveSignedElements(wrapped, parse(wrapped), [
      key.certificatePem,
    ]);
    expect(element.localName).toBe('Assertion');
  });

  // The spec promises PEM or base64 DER, and metadata carries the latter.
  // Measured: xml-crypto throws DECODER routines::unsupported on bare base64,
  // and the same bytes armoured verify — so this is a real conversion, not a
  // formatting preference. Normalising is the caller's job, not
  // resolveSignedElements's: the validator (a later task) proves and
  // normalises each certificate with toPem at construction, so
  // resolveSignedElements itself only ever receives PEM.
  it('accepts a certificate given as bare base64 DER', () => {
    const key = generateKeyMaterial();
    const der = key.certificatePem
      .replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, '');
    const signed = signXml(ASSERTION(), key);
    const wrapped = RESPONSE(signed);
    const [element] = resolveSignedElements(wrapped, parse(wrapped), [
      toPem(der),
    ]);
    expect(element.localName).toBe('Assertion');

    // Passed raw, without the caller's normalisation, the same bytes are
    // rejected — pinning that the conversion is real work, not a no-op.
    expect(() => resolveSignedElements(wrapped, parse(wrapped), [der])).toThrow(
      /does not verify/,
    );
  });

  it('refuses a certificate that is neither PEM nor base64', () => {
    expect(() => toPem('not a certificate!')).toThrow(
      /neither PEM nor base64/i,
    );
  });

  // Base64 syntax is not enough: this armours cleanly, and only OpenSSL knows
  // it is not a certificate. Without the X509Certificate parse it would reach
  // verification and be reported as a bad signature — the configuration
  // blamed on the assertion again.
  it('refuses base64 that is not a certificate', () => {
    expect(() => toPem('AAAA')).toThrow(/not a valid X.509 certificate/i);
  });

  it('accepts a certificate later in the rotation list', () => {
    const other = generateKeyMaterial();
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key);
    const wrapped = RESPONSE(signed);
    const [element] = resolveSignedElements(wrapped, parse(wrapped), [
      other.certificatePem,
      key.certificatePem,
    ]);
    expect(element.localName).toBe('Assertion');
  });

  it('refuses a document with no signature', () => {
    const wrapped = RESPONSE(ASSERTION());
    expect(() => resolveSignedElements(wrapped, parse(wrapped), ['x'])).toThrow(
      /no signature/i,
    );
  });

  it('refuses a signature made with a key we do not trust', () => {
    const key = generateKeyMaterial();
    const other = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key);
    const wrapped = RESPONSE(signed);
    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [other.certificatePem]),
    ).toThrow(/signature does not verify/i);
  });

  // The attacker signs with their own key and puts their own certificate in
  // KeyInfo. xml-crypto consults getCertFromKeyInfo before publicCert, so a
  // verifier that honoured KeyInfo would check the attacker's signature
  // against the attacker's certificate — and pass.
  it('ignores a certificate the document carries in its own KeyInfo', () => {
    const trusted = generateKeyMaterial();
    const attacker = generateKeyMaterial();
    const attackerBody = attacker.certificatePem
      .replace(/-----[^-]+-----/g, '')
      .replace(/\s+/g, '');
    const sig = new SignedXml({
      privateKey: attacker.privateKeyPem,
      publicCert: attacker.certificatePem,
      signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
      getKeyInfoContent: () =>
        `<X509Data><X509Certificate>${attackerBody}</X509Certificate></X509Data>`,
    });
    sig.addReference({
      xpath: "//*[local-name(.)='Assertion']",
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
      ],
    });
    sig.computeSignature(ASSERTION(), {
      location: {
        reference: "//*[local-name(.)='Issuer']",
        action: 'after',
      },
    });
    const wrapped = RESPONSE(sig.getSignedXml());
    // The premise: the attacker's certificate really is in KeyInfo.
    expect(wrapped).toContain(`<X509Certificate>${attackerBody}`);

    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [
        toPem(trusted.certificatePem),
      ]),
    ).toThrow(/does not verify/);
  });

  it('refuses content altered after signing', () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION(), key).replace('mock-idp', 'other-idp');
    const wrapped = RESPONSE(signed);
    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [key.certificatePem]),
    ).toThrow(/signature does not verify/i);
  });

  // The attack this function exists for: a validly signed assertion beside a
  // forged one. Whatever is returned must be the signed element, and the
  // caller reads only that.
  it('refuses a signature detached from the element it references', () => {
    const key = generateKeyMaterial();
    // Lift the Signature out of the Assertion and into the Response. The bytes
    // it covers are unchanged, so it still verifies — only the parent check
    // catches this.
    const signed = signXml(ASSERTION(), key);
    const signature =
      /<[^>]*Signature[\s\S]*<\/[^>]*Signature>/.exec(signed)?.[0] ?? '';
    const wrapped = RESPONSE(`${signed.replace(signature, '')}${signature}`);
    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [key.certificatePem]),
    ).toThrow(/does not envelope/i);
  });

  it('refuses a signature with an empty URI that sits below the root', () => {
    const key = generateKeyMaterial();
    // An empty URI signs the whole document, so the element it references is
    // the root. Placing the Signature inside the Assertion still verifies —
    // the enveloped-signature transform removes it before digesting, wherever
    // it sits — but its parent is then the Assertion, not the root. Only the
    // enveloping check catches that, and an early return for the empty-URI
    // case is exactly how the check stops applying.
    //
    // Rewriting URI in an already-signed document would not do: URI lives
    // inside SignedInfo, which is itself signed, so the edit breaks
    // SignatureValue and the test would fail at "does not verify" instead —
    // passing for the wrong reason, or rather failing for it.
    const unsigned = RESPONSE(ASSERTION());
    const sig = new SignedXml({
      privateKey: key.privateKeyPem,
      publicCert: key.certificatePem,
      signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    });
    sig.addReference({
      xpath: '/*',
      uri: '',
      // Without this, xml-crypto calls ensureHasId() on the referenced node
      // and overwrites `uri` with "#<id>" — the fixture would be an ordinary
      // reference and would test nothing about the empty-URI path. Verified
      // against the installed xml-crypto, whose signed-xml.js branches on
      // isEmptyUri at exactly that point.
      isEmptyUri: true,
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
      ],
    });
    sig.computeSignature(unsigned, {
      location: {
        reference: "//*[local-name(.)='Assertion']",
        action: 'append',
      },
    });
    const wrapped = sig.getSignedXml();

    // The fixture must be what it claims before it can prove anything: a setup
    // that silently produced a different document would pass or fail for a
    // reason nobody chose.
    expect(wrapped).toContain('URI=""');

    // And it must verify, or this tests the signature check rather than the
    // enveloping one. Measured against the installed xml-crypto: an empty-URI
    // signature nested inside the Assertion returns true here, because the
    // enveloped-signature transform removes it wherever it sits. If a future
    // version stops verifying it, this line fails with a clear reason instead
    // of the case below passing for the wrong one.
    const probe = new SignedXml({ publicCert: key.certificatePem });
    probe.loadSignature(
      parse(wrapped).getElementsByTagNameNS(
        'http://www.w3.org/2000/09/xmldsig#',
        'Signature',
      )[0] as never,
    );
    expect(probe.checkSignature(wrapped)).toBe(true);

    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [key.certificatePem]),
    ).toThrow(/does not envelope/i);
  });

  it('refuses a signature carrying more than one reference', () => {
    const key = generateKeyMaterial();
    // Signed directly with two references, rather than duplicating a
    // <Reference> in an already-signed document: <Reference> is a child of
    // <SignedInfo>, so copying one changes SignedInfo's canonicalised bytes
    // and breaks SignatureValue — the reference-count check would never be
    // reached, only "does not verify".
    const signer = new SignedXml({
      privateKey: key.privateKeyPem,
      canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
      signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    });
    const reference = {
      xpath: "//*[local-name(.)='Assertion']",
      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
      ],
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
    };
    signer.addReference(reference);
    signer.addReference(reference);
    signer.computeSignature(ASSERTION(), {
      location: { reference: reference.xpath, action: 'append' },
    });
    const wrapped = RESPONSE(signer.getSignedXml());

    // The fixture must actually verify, or this tests the signature check
    // rather than the reference-count one.
    const probe = new SignedXml({ publicCert: key.certificatePem });
    probe.loadSignature(
      parse(wrapped).getElementsByTagNameNS(
        'http://www.w3.org/2000/09/xmldsig#',
        'Signature',
      )[0] as never,
    );
    expect(probe.checkSignature(wrapped)).toBe(true);

    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [key.certificatePem]),
    ).toThrow(/the signature carries 2 ds:Reference; exactly one is allowed/);
  });

  // xml-crypto finds SignedInfo's References by local name in any namespace;
  // this module counts only ds:Reference. A Reference moved to another
  // namespace therefore verifies under xml-crypto and counts as none here —
  // the only way a verified signature reaches the zero case, since with no
  // Reference at all xml-crypto's loadSignature throws first.
  it('refuses a signature carrying no ds:Reference', () => {
    const key = generateKeyMaterial();
    const wrapped = signWithPatchedReference(key, (reference, doc) => {
      const moved = doc.createElementNS('urn:not-xmldsig', 'x:Reference');
      moved.setAttribute('URI', reference.getAttribute('URI') ?? '');
      while (reference.firstChild) moved.appendChild(reference.firstChild);
      reference.parentNode?.replaceChild(moved, reference);
    });
    expect(wrapped).toContain('<x:Reference');
    expect(xmlCryptoVerifies(wrapped, key)).toBe(true);

    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [key.certificatePem]),
    ).toThrow(/the signature carries no ds:Reference/);
  });

  it('returns the signed assertion, not the forged sibling', () => {
    const key = generateKeyMaterial();
    const signed = signXml(ASSERTION('_real'), key);
    const forged = ASSERTION('_forged').replace('mock-idp', 'attacker');
    const wrapped = RESPONSE(`${forged}${signed}`);
    const [element] = resolveSignedElements(wrapped, parse(wrapped), [
      key.certificatePem,
    ]);
    expect(element.getAttribute('ID')).toBe('_real');
  });

  // Identity providers often sign both levels — Keycloak does by default. The
  // Assertion is signed first, then the Response around it, with the
  // Response's Signature as its first child (this fixture has no Response
  // Issuer; with one, the Signature goes right after it).
  const doubleSigned = (
    assertionKey: ReturnType<typeof generateKeyMaterial>,
    responseKey = assertionKey,
  ) =>
    signXml(RESPONSE(signXml(ASSERTION(), assertionKey)), responseKey, {
      referenceXPath: "//*[local-name(.)='Response']",
      location: {
        reference: "//*[local-name(.)='Response']",
        action: 'prepend',
      },
    });

  it('returns both elements when the Response and the Assertion are signed', () => {
    const key = generateKeyMaterial();
    const xml = doubleSigned(key);
    const covered = resolveSignedElements(xml, parse(xml), [
      key.certificatePem,
    ]);
    expect(covered.map((e) => e.localName).sort()).toEqual([
      'Assertion',
      'Response',
    ]);
  });

  it('refuses the document when one of two signatures does not verify', () => {
    const key = generateKeyMaterial();
    const untrusted = generateKeyMaterial();
    // The Assertion is signed by a trusted key, the Response by another: the
    // Assertion alone would pass, and the document must still be refused.
    const xml = doubleSigned(key, untrusted);
    expect(() =>
      resolveSignedElements(xml, parse(xml), [key.certificatePem]),
    ).toThrow(/does not verify against any configured certificate/);
  });

  // A verifier that stops checking after the first signature is exactly the
  // shape this attack needs: a legitimate signature placed first buys trust
  // for the whole document, and a second, forged signature riding along
  // behind it is never checked. doubleSigned's first argument signs the
  // Assertion, which is nested inside the Response and so comes second in
  // document order; its second argument signs the Response, prepended as the
  // Response's first child and so comes first. `doubleSigned(untrusted, key)`
  // therefore puts the trusted signature first and the untrusted one second —
  // the reverse of the case above — and every signature must still be
  // checked for the document to be refused.
  it('refuses the document when the untrusted signature comes after a trusted one', () => {
    const key = generateKeyMaterial();
    const untrusted = generateKeyMaterial();
    const xml = doubleSigned(untrusted, key);
    expect(() =>
      resolveSignedElements(xml, parse(xml), [key.certificatePem]),
    ).toThrow(/does not verify against any configured certificate/);
  });

  // The same attack without any nesting to rely on: two Assertions as
  // siblings, the first genuinely signed by a trusted key, the second by a
  // key nobody configured. A verifier that only checks the first signature it
  // finds would return both elements as "covered".
  it('refuses the document when a trusted signature has an untrusted sibling', () => {
    const key = generateKeyMaterial();
    const untrusted = generateKeyMaterial();
    const wrapped = RESPONSE(
      `${signXml(ASSERTION('_a'), key)}${signXml(ASSERTION('_b'), untrusted)}`,
    );
    expect(() =>
      resolveSignedElements(wrapped, parse(wrapped), [key.certificatePem]),
    ).toThrow(/does not verify against any configured certificate/);
  });
});
