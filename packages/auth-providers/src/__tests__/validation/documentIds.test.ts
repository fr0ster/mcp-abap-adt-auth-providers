import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { DOMParser, type Document, type Element } from '@xmldom/xmldom';
import { findDuplicateId, readRequiredId } from '../../validation/documentIds';

const parse = (xml: string) =>
  new DOMParser().parseFromString(xml, 'text/xml') as unknown as Document;

describe('findDuplicateId', () => {
  it('passes a document whose IDs are unique', () => {
    const doc = parse('<r ID="_a"><c ID="_b"/><c ID="_c"/></r>');
    assert.equal(findDuplicateId(doc), null);
  });

  it('names the value that appears twice', () => {
    const doc = parse('<r ID="_a"><c ID="_dup"/><c ID="_dup"/></r>');
    assert.equal(findDuplicateId(doc), '_dup');
  });

  // The wrapping shape: the duplicate is between the root and a nested
  // element, not between siblings.
  it('finds a duplicate shared between an ancestor and a descendant', () => {
    const doc = parse('<r ID="_same"><c ID="_same"/></r>');
    assert.equal(findDuplicateId(doc), '_same');
  });

  it('ignores elements with no ID at all', () => {
    const doc = parse('<r ID="_a"><c/><c/></r>');
    assert.equal(findDuplicateId(doc), null);
  });
});

describe('readRequiredId', () => {
  it('returns the ID', () => {
    const doc = parse('<a ID="_x"/>');
    assert.equal(
      readRequiredId(doc.documentElement as unknown as Element),
      '_x',
    );
  });

  it('returns null when the attribute is absent', () => {
    const doc = parse('<a/>');
    assert.equal(
      readRequiredId(doc.documentElement as unknown as Element),
      null,
    );
  });

  it('returns null when the attribute is empty', () => {
    const doc = parse('<a ID=""/>');
    assert.equal(
      readRequiredId(doc.documentElement as unknown as Element),
      null,
    );
  });

  // The absent case exercised directly, not only through @xmldom/xmldom 0.9
  // returning null. xml-crypto nests xmldom 0.8, whose getAttribute returns
  // '' for an absent attribute; both must read as "no ID".
  it('returns null for an absent attribute reported as null', () => {
    const element = { getAttribute: () => null } as unknown as Element;
    assert.equal(readRequiredId(element), null);
  });

  it("returns null for an absent attribute reported as ''", () => {
    const element = { getAttribute: () => '' } as unknown as Element;
    assert.equal(readRequiredId(element), null);
  });
});
