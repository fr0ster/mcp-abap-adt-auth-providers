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
 * The Assertion is serialised as an element of its own, and every namespace
 * declaration it inherited from the Response is copied onto it first. A
 * serializer would add back only the prefixes used in element and attribute
 * names; a prefix used only inside a value — `xsi:type="xs:string"` — would be
 * lost, leaving a QName that no longer resolves. Copying all of them keeps the
 * Assertion's in-scope namespaces exactly what they were. Its signature, over
 * exclusive canonical XML, still verifies: canonicalisation renders a
 * namespace where it is used, or where the signature's InclusiveNamespaces
 * names it, not where it was declared. A signature over the Response alone does not
 * survive the cut; the token endpoint then refuses the Assertion, as it
 * would any unsigned one.
 */

import { type Element, XMLSerializer } from '@xmldom/xmldom';
import { quoteUntrusted } from '../validation/signedNode';
import { parseStrictXml } from './strictXml';

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
    root = parseStrictXml(xml).documentElement;
  } catch (error) {
    // The parser quotes the document (an element name, for one), so its
    // message is quoted and cut like any other document value in a message.
    throw new Error(
      `SAML bearer payload is not well-formed XML: ${quoteUntrusted(error instanceof Error ? error.message : String(error))}`,
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

  const assertion = assertions[0];
  declareInheritedNamespaces(assertion);
  const serialized = new XMLSerializer().serializeToString(assertion);
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

const XMLNS_NS = 'http://www.w3.org/2000/xmlns/';

const isNamespaceDeclaration = (name: string): boolean =>
  name === 'xmlns' || name.startsWith('xmlns:');

/**
 * Copies onto `element` every namespace declaration in scope from its
 * ancestors that it does not make itself. Ancestors are walked innermost
 * first, so the nearest declaration of a prefix wins, as it did in place.
 */
function declareInheritedNamespaces(element: Element): void {
  const declared = new Set<string>();
  for (let i = 0; i < element.attributes.length; i++) {
    const name = element.attributes.item(i)?.name;
    if (name && isNamespaceDeclaration(name)) declared.add(name);
  }
  for (
    let ancestor = element.parentNode;
    ancestor && ancestor.nodeType === 1;
    ancestor = ancestor.parentNode
  ) {
    const attributes = (ancestor as Element).attributes;
    for (let i = 0; i < attributes.length; i++) {
      const attribute = attributes.item(i);
      if (
        attribute &&
        isNamespaceDeclaration(attribute.name) &&
        !declared.has(attribute.name)
      ) {
        element.setAttributeNS(XMLNS_NS, attribute.name, attribute.value);
        declared.add(attribute.name);
      }
    }
  }
}

function childElements(parent: Element): Element[] {
  const out: Element[] = [];
  for (let n = parent.firstChild; n; n = n.nextSibling) {
    if (n.nodeType === 1) out.push(n as Element);
  }
  return out;
}
