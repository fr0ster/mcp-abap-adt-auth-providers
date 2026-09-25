/**
 * Parsing untrusted XML so that any fault is a refusal.
 *
 * @xmldom/xmldom's defaults are wrong for a security boundary in two ways:
 * without `onError` it reports every fault to the console — so a malformed
 * callback from anyone writes to the process's stderr, past `ILogger` — and it
 * recovers from `error`-level faults (an undeclared entity, say) by handing
 * back a repaired document instead of failing. Throwing from `onError` turns
 * every level into a `ParseError`, silently.
 */

import { DOMParser, type Document } from '@xmldom/xmldom';

export function parseStrictXml(xml: string): Document {
  return new DOMParser({
    onError: (level, message) => {
      throw new Error(`XML ${level}: ${message}`);
    },
  }).parseFromString(xml, 'text/xml');
}
