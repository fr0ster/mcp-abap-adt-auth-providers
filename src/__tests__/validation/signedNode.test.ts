import { describe, expect, it } from '@jest/globals';
import { generateKeyMaterial, signXml } from '@mcp-abap-adt/auth-mocks';
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
    ).toThrow(/exactly one is required/i);
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
});
