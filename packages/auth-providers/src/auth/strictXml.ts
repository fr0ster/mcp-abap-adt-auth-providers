/**
 * Parsing untrusted XML so that any fault is a refusal.
 *
 * @xmldom/xmldom's defaults are wrong for a security boundary in two ways:
 * without `onError` it reports every fault to the console — so a malformed
 * callback from anyone writes to the process's stderr, past `ILogger` — and it
 * recovers from `error`-level faults (an undeclared entity, say) by handing
 * back a repaired document instead of failing. Throwing from `onError` turns
 * every level into a refusal, silently.
 *
 * What is thrown is the `not-xml` rule and nothing of the
 * parser's message, which quotes the document. A caller with a rule of
 * its own — the bearer conversion's `payload-not-well-formed` — catches it
 * and refuses with that rule instead.
 */

import { authError } from '@mcp-abap-adt/auth-errors';
import { DOMParser, type Document } from '@xmldom/xmldom';
import { refuse } from '../validation/samlRefusal';

/** The `not-xml` rule, thrown. */
function notXml(): never {
  return refuse(
    authError['saml-assertion']({ rule: 'not-xml', check: 'document' }),
  );
}

export function parseStrictXml(xml: string): Document {
  try {
    return new DOMParser({
      // xmldom may wrap whatever this throws in a ParseError that quotes the
      // document; the catch below drops that error whole.
      onError: notXml,
    }).parseFromString(xml, 'text/xml');
  } catch {
    return notXml();
  }
}
