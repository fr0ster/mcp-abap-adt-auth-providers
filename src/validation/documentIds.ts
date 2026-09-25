import type { Document, Element } from '@xmldom/xmldom';

/**
 * The `ID` rules, which run before any signature reference is resolved.
 *
 * XML-DSig resolves its reference by `ID`. Two elements sharing one make
 * "which element is signed" a question the parser answers rather than the
 * specification, and that ambiguity is the classic lever for signature
 * wrapping. So uniqueness is established first, across the whole document —
 * not only across the two elements this validator happens to read.
 */

/** The first ID value appearing more than once, or null when all are unique. */
export function findDuplicateId(doc: Document): string | null {
  const seen = new Set<string>();
  const elements = doc.getElementsByTagName('*');
  for (let i = 0; i < elements.length; i++) {
    const id = elements[i].getAttribute('ID');
    if (!id) continue;
    if (seen.has(id)) return id;
    seen.add(id);
  }
  return null;
}

/** The element's ID, or null when it is absent or empty. */
export function readRequiredId(element: Element): string | null {
  const id = element.getAttribute('ID');
  return id ? id : null;
}
