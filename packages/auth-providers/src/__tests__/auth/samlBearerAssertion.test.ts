/**
 * Turning what a SAML login delivers into what RFC 7522 §2.1 accepts: one
 * Assertion, base64url-encoded.
 */

import assert from 'node:assert/strict';
import { describe, it, mock } from 'node:test';
import { DOMParser } from '@xmldom/xmldom';
import { toBearerAssertion } from '../../auth/samlBearerAssertion';
import { parseStrictXml } from '../../auth/strictXml';
import {
  cases,
  caseTitle,
  contains,
  notContains,
} from '../helpers/expectations';
import { expectSamlRefusal, thrownBy } from '../helpers/samlRefusal';

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
  assert.match(value, /^[A-Za-z0-9_-]+$/); // base64url: no +, / or padding
  const xml = Buffer.from(value, 'base64url').toString('utf8');
  return new DOMParser().parseFromString(xml, 'text/xml').documentElement;
};

describe('toBearerAssertion', () => {
  it('takes the Assertion out of a base64 SAMLResponse', () => {
    const root = decoded(toBearerAssertion(b64(response(assertion()))));

    assert.equal(root?.localName, 'Assertion');
    assert.equal(root?.namespaceURI, ASSERTION_NS);
    assert.equal(root?.getAttribute('ID'), '_a1');
  });

  it('keeps the Assertion’s signature', () => {
    const root = decoded(toBearerAssertion(b64(response(assertion()))));

    const signatures = root?.getElementsByTagNameNS(
      'http://www.w3.org/2000/09/xmldsig#',
      'Signature',
    );
    assert.equal(signatures?.length, 1);
  });

  it('declares a namespace the Assertion only inherited from the Response', () => {
    const root = decoded(toBearerAssertion(b64(response(assertion(false)))));

    assert.equal(root?.namespaceURI, ASSERTION_NS);
    assert.equal(
      root?.getElementsByTagNameNS(ASSERTION_NS, 'NameID').length,
      1,
    );
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
    assert.equal(root?.lookupNamespaceURI('types'), 'urn:example:types');
    const value = root?.getElementsByTagNameNS(
      ASSERTION_NS,
      'AttributeValue',
    )[0];
    assert.equal(value?.getAttribute('xsi:type'), 'types:Role');
  });

  it('keeps a declaration the Assertion makes itself over an ancestor’s', () => {
    const xml =
      '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ' +
      `xmlns:saml2="${ASSERTION_NS}" xmlns:t="urn:outer">` +
      '<saml2:Assertion xmlns:t="urn:inner" ID="_a1"/></samlp:Response>';

    const root = decoded(toBearerAssertion(b64(xml)));

    assert.equal(root?.lookupNamespaceURI('t'), 'urn:inner');
  });

  it('re-encodes a bare Assertion sent in standard base64', () => {
    const xml = assertion();
    assert.equal(toBearerAssertion(b64(xml)), b64url(xml));
  });

  it('passes a bare Assertion already in base64url through unchanged', () => {
    const value = b64url(assertion());
    assert.equal(toBearerAssertion(value), value);
  });

  it('refuses a Response carrying no Assertion', () => {
    expectSamlRefusal(
      thrownBy(() => toBearerAssertion(b64(response('')))),
      'no-assertion',
    );
  });

  // The count is a fact, and the words name it.
  it('refuses a Response carrying more than one Assertion', () => {
    const error = expectSamlRefusal(
      thrownBy(() =>
        toBearerAssertion(b64(response(assertion() + assertion()))),
      ),
      'several-assertions',
      { facts: { count: 2 } },
    );
    contains(
      error.reason,
      'SAML Response carries 2 Assertions; a bearer grant takes one',
    );
  });

  it('refuses an encrypted Assertion rather than sending something UAA cannot read', () => {
    const encrypted = response(
      `<saml2:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml2:EncryptedAssertion>`,
    );
    const error = expectSamlRefusal(
      thrownBy(() => toBearerAssertion(b64(encrypted))),
      'only-encrypted-assertion',
    );
    contains(error.reason, 'encrypted Assertions are not supported');
  });

  it('refuses a document that is neither a Response nor an Assertion', () => {
    expectSamlRefusal(
      thrownBy(() =>
        toBearerAssertion(
          b64(
            '<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>',
          ),
        ),
      ),
      'payload-not-saml',
    );
  });

  it('refuses a payload that is not base64-encoded XML', () => {
    expectSamlRefusal(
      thrownBy(() => toBearerAssertion('not-xml-at-all')),
      'payload-not-base64-xml',
    );
  });
  // Same parser rule as the validator: any XML fault is a refusal, and the
  // parser never writes to the console on its own.
  it('refuses XML the parser would recover from, and writes nothing to the console', () => {
    const spies = (['error', 'warn', 'log'] as const).map((level) =>
      mock.method(console, level, () => undefined),
    );
    try {
      const recoverable = `<saml:Assertion xmlns:saml="${ASSERTION_NS}" ID="_a">&bogus;</saml:Assertion>`;
      expectSamlRefusal(
        thrownBy(() =>
          toBearerAssertion(
            Buffer.from(recoverable, 'utf8').toString('base64'),
          ),
        ),
        'payload-not-well-formed',
      );
      for (const spy of spies) assert.equal(spy.mock.callCount(), 0);
    } finally {
      for (const spy of spies) spy.mock.restore();
    }
  });

  // The parser's message quotes the document — here an element
  // name — and none of it reaches the error: not the words, not a
  // diagnostic (the rule has none), not the failure's message.
  it('says nothing of the parser message for XML that is not well-formed', () => {
    const name = 'x'.repeat(100);
    const thrown = thrownBy(() =>
      toBearerAssertion(
        Buffer.from(`<${name}><y></${name}>`, 'utf8').toString('base64'),
      ),
    );
    const error = expectSamlRefusal(thrown, 'payload-not-well-formed');
    assert.equal(
      error.reason,
      'the SAML assertion was refused (document): SAML bearer payload is not well-formed XML',
    );
    notContains(JSON.stringify(thrown), 'xxxx');
    notContains(String(thrown), 'xxxx');
  });
});

/** The strict parser's own refusal, with no parser text. */
describe('parseStrictXml', () => {
  for (const [caseIndex, caseRow] of cases([
    ['an unterminated document', '<a'],
    ['an undeclared entity the parser would repair', '<a>&secret-entity;</a>'],
    ['a tag mismatch', '<abc></xyz>'],
    ['no root element', 'not xml'],
    ['a redefined attribute', '<a secret="1" secret="2"/>'],
  ]).entries()) {
    const [_name, xml] = caseRow;
    it(
      caseTitle(
        'refuses %s with not-xml, naming nothing of it',
        caseRow,
        caseIndex,
      ),
      () => {
        const thrown = thrownBy(() => parseStrictXml(xml));
        expectSamlRefusal(thrown, 'not-xml');
        assert.doesNotMatch(JSON.stringify(thrown), /secret|xyz|abc|entity/);
        assert.doesNotMatch(String(thrown), /secret|xyz|abc|entity/);
      },
    );
  }
});
