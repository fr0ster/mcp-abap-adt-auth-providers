import { describe, expect, it } from '@jest/globals';
import { DOMParser, type Document, type Element } from '@xmldom/xmldom';
import { findDuplicateId, readRequiredId } from '../../validation/documentIds';

const parse = (xml: string) =>
  new DOMParser().parseFromString(xml, 'text/xml') as unknown as Document;

describe('findDuplicateId', () => {
  it('passes a document whose IDs are unique', () => {
    const doc = parse('<r ID="_a"><c ID="_b"/><c ID="_c"/></r>');
    expect(findDuplicateId(doc)).toBeNull();
  });

  it('names the value that appears twice', () => {
    const doc = parse('<r ID="_a"><c ID="_dup"/><c ID="_dup"/></r>');
    expect(findDuplicateId(doc)).toBe('_dup');
  });

  // The wrapping shape: the duplicate is between the root and a nested
  // element, not between siblings.
  it('finds a duplicate shared between an ancestor and a descendant', () => {
    const doc = parse('<r ID="_same"><c ID="_same"/></r>');
    expect(findDuplicateId(doc)).toBe('_same');
  });

  it('ignores elements with no ID at all', () => {
    const doc = parse('<r ID="_a"><c/><c/></r>');
    expect(findDuplicateId(doc)).toBeNull();
  });
});

describe('readRequiredId', () => {
  it('returns the ID', () => {
    const doc = parse('<a ID="_x"/>');
    expect(readRequiredId(doc.documentElement as unknown as Element)).toBe(
      '_x',
    );
  });

  it('returns null when the attribute is absent', () => {
    const doc = parse('<a/>');
    expect(
      readRequiredId(doc.documentElement as unknown as Element),
    ).toBeNull();
  });

  it('returns null when the attribute is empty', () => {
    const doc = parse('<a ID=""/>');
    expect(
      readRequiredId(doc.documentElement as unknown as Element),
    ).toBeNull();
  });
});
