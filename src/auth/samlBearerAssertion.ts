/**
 * What the SAML 2.0 bearer grant accepts, from what a SAML login delivers.
 *
 * RFC 7522 §2.1: the `assertion` parameter is a single SAML 2.0 Assertion,
 * base64url-encoded. An interactive login delivers something else — the
 * identity provider's whole `samlp:Response`, in standard base64 — and a
 * token endpoint that follows the RFC refuses it: Cloud Foundry UAA answers
 * 401 to a Response in either encoding. So the Assertion is taken out of the
 * Response here and re-encoded.
 *
 * The Assertion is serialised as an element of its own. A namespace it only
 * inherited from the Response is declared on it, so it still parses — and its
 * signature, computed over exclusive canonical XML, still verifies, since
 * exclusive canonicalisation renders the namespaces an element uses no matter
 * where they were declared. A signature over the Response alone does not
 * survive the cut; the token endpoint then refuses the Assertion, as it
 * would any unsigned one.
 */

import { DOMParser, type Element, XMLSerializer } from '@xmldom/xmldom';

const SAML_ASSERTION_NS = 'urn:oasis:names:tc:SAML:2.0:assertion';
const SAML_PROTOCOL_NS = 'urn:oasis:names:tc:SAML:2.0:protocol';

export function toBearerAssertion(payload: string): string {
  // Node's base64 decoder accepts both alphabets, so this reads either.
  const xml = Buffer.from(payload.trim(), 'base64').toString('utf8');
  if (!xml.trimStart().startsWith('<')) {
    throw new Error('SAML bearer payload is not base64-encoded XML');
  }

  let root: Element | null;
  try {
    root = new DOMParser().parseFromString(xml, 'text/xml').documentElement;
  } catch (error) {
    throw new Error(
      `SAML bearer payload is not well-formed XML: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (isElement(root, SAML_ASSERTION_NS, 'Assertion')) {
    return Buffer.from(xml, 'utf8').toString('base64url');
  }
  if (!isElement(root, SAML_PROTOCOL_NS, 'Response')) {
    throw new Error(
      'SAML bearer payload is neither a SAML Response nor an Assertion',
    );
  }

  const children = childElements(root);
  const assertions = children.filter((e) =>
    isElement(e, SAML_ASSERTION_NS, 'Assertion'),
  );
  if (assertions.length === 0) {
    if (
      children.some((e) =>
        isElement(e, SAML_ASSERTION_NS, 'EncryptedAssertion'),
      )
    ) {
      throw new Error(
        'SAML Response carries only an EncryptedAssertion; encrypted Assertions are not supported',
      );
    }
    throw new Error('SAML Response carries no Assertion');
  }
  if (assertions.length > 1) {
    throw new Error(
      `SAML Response carries ${assertions.length} Assertions; a bearer grant takes one`,
    );
  }

  const serialized = new XMLSerializer().serializeToString(assertions[0]);
  return Buffer.from(serialized, 'utf8').toString('base64url');
}

function isElement(
  node: Element | null | undefined,
  namespace: string,
  localName: string,
): node is Element {
  return (
    !!node && node.namespaceURI === namespace && node.localName === localName
  );
}

function childElements(parent: Element): Element[] {
  const out: Element[] = [];
  for (let n = parent.firstChild; n; n = n.nextSibling) {
    if (n.nodeType === 1) out.push(n as Element);
  }
  return out;
}
