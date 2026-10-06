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
 * What is thrown is the `not-xml` rule (spec A.6, F7) and nothing of the
 * parser's message, which quotes the document (L7). A caller with a rule of
 * its own — the bearer conversion's `payload-not-well-formed` — catches it
 * and refuses with that rule instead.
 */

import { authError } from '@mcp-abap-adt/auth-errors';
import { DOMParser, type Document } from '@xmldom/xmldom';
import { refuse } from '../validation/samlRefusal';

export function parseStrictXml(xml: string): Document {
  try {
    return new DOMParser({
      // Fixed words: xmldom wraps whatever this throws in a ParseError that
      // quotes the document, and the catch below drops that error whole.
      onError: () => {
        throw new Error('the XML did not parse');
      },
    }).parseFromString(xml, 'text/xml');
  } catch {
    return refuse(
      authError['saml-assertion']({ rule: 'not-xml', check: 'document' }),
    );
  }
}
