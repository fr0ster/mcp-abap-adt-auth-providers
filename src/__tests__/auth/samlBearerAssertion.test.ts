/**
 * Turning what a SAML login delivers into what RFC 7522 §2.1 accepts: one
 * Assertion, base64url-encoded.
 */

import { describe, expect, it } from '@jest/globals';
import { DOMParser } from '@xmldom/xmldom';
import { toBearerAssertion } from '../../auth/samlBearerAssertion';

const ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';

const assertion = (declareNs = true) =>
  `<saml2:Assertion${declareNs ? ` xmlns:saml2="${ASSERTION_NS}"` : ''} ID="_a1" Version="2.0">` +
  '<saml2:Issuer>idp</saml2:Issuer>' +
  '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignatureValue>c2ln</ds:SignatureValue></ds:Signature>' +
  '<saml2:Subject><saml2:NameID>user</saml2:NameID></saml2:Subject>' +
  '</saml2:Assertion>';

const response = (inner: string) =>
  '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
  `xmlns:saml2="${ASSERTION_NS}" ID="_r1" Version="2.0">` +
  '<saml2:Issuer>idp</saml2:Issuer>' +
  '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>' +
  `${inner}</samlp:Response>`;

const b64 = (xml: string) => Buffer.from(xml, 'utf8').toString('base64');
const b64url = (xml: string) => Buffer.from(xml, 'utf8').toString('base64url');

/** Decode the result and parse it, so assertions are about XML, not bytes. */
const decoded = (value: string) => {
  expect(value).toMatch(/^[A-Za-z0-9_-]+$/); // base64url: no +, / or padding
  const xml = Buffer.from(value, 'base64url').toString('utf8');
  return new DOMParser().parseFromString(xml, 'text/xml').documentElement;
};

describe('toBearerAssertion', () => {
  it('takes the Assertion out of a base64 SAMLResponse', () => {
    const root = decoded(toBearerAssertion(b64(response(assertion()))));

    expect(root?.localName).toBe('Assertion');
    expect(root?.namespaceURI).toBe(ASSERTION_NS);
    expect(root?.getAttribute('ID')).toBe('_a1');
  });

  it('keeps the Assertion’s signature', () => {
    const root = decoded(toBearerAssertion(b64(response(assertion()))));

    const signatures = root?.getElementsByTagNameNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Signature',
    );
    expect(signatures?.length).toBe(1);
  });

  it('declares a namespace the Assertion only inherited from the Response', () => {
    const root = decoded(toBearerAssertion(b64(response(assertion(false)))));

    expect(root?.namespaceURI).toBe(ASSERTION_NS);
    expect(root?.getElementsByTagNameNS(ASSERTION_NS, 'NameID').length).toBe(1);
  });

  it('declares a namespace used only inside an attribute value (xsi:type QName)', () => {
    const xml =
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
      `xmlns:saml2="${ASSERTION_NS}" ` +
      'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:types="urn:example:types">' +
      '<saml2:Assertion ID="_a1"><saml2:AttributeStatement><saml2:Attribute Name="role">' +
      '<saml2:AttributeValue xsi:type="types:Role">admin</saml2:AttributeValue>' +
      '</saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></samlp:Response>';

    const root = decoded(toBearerAssertion(b64(xml)));

    // A serializer carries prefixes used in names; `types` is used only in a
    // value, so it has to be declared on purpose.
    expect(root?.lookupNamespaceURI('types')).toBe('urn:example:types');
    const value = root?.getElementsByTagNameNS(
      ASSERTION_NS,
      'AttributeValue',
    )[0];
    expect(value?.getAttribute('xsi:type')).toBe('types:Role');
  });

  it('keeps a declaration the Assertion makes itself over an ancestor’s', () => {
    const xml =
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
      `xmlns:saml2="${ASSERTION_NS}" xmlns:t="urn:outer">` +
      '<saml2:Assertion xmlns:t="urn:inner" ID="_a1"/></samlp:Response>';

    const root = decoded(toBearerAssertion(b64(xml)));

    expect(root?.lookupNamespaceURI('t')).toBe('urn:inner');
  });

  it('re-encodes a bare Assertion sent in standard base64', () => {
    const xml = assertion();
    expect(toBearerAssertion(b64(xml))).toBe(b64url(xml));
  });

  it('passes a bare Assertion already in base64url through unchanged', () => {
    const value = b64url(assertion());
    expect(toBearerAssertion(value)).toBe(value);
  });

  it('refuses a Response carrying no Assertion', () => {
    expect(() => toBearerAssertion(b64(response('')))).toThrow(
      'SAML Response carries no Assertion',
    );
  });

  it('refuses a Response carrying more than one Assertion', () => {
    expect(() =>
      toBearerAssertion(b64(response(assertion() + assertion()))),
    ).toThrow('SAML Response carries 2 Assertions; a bearer grant takes one');
  });

  it('refuses an encrypted Assertion rather than sending something UAA cannot read', () => {
    const encrypted = response(
      `<saml2:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml2:EncryptedAssertion>`,
    );
    expect(() => toBearerAssertion(b64(encrypted))).toThrow(
      'encrypted Assertions are not supported',
    );
  });

  it('refuses a document that is neither a Response nor an Assertion', () => {
    expect(() =>
      toBearerAssertion(
        b64(
          '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>',
        ),
      ),
    ).toThrow('neither a SAML Response nor an Assertion');
  });

  it('refuses a payload that is not base64-encoded XML', () => {
    expect(() => toBearerAssertion('not-xml-at-all')).toThrow(
      'not base64-encoded XML',
    );
  });
});
