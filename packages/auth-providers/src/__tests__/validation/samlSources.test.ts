/**
 * Source tests for the SAML path:
 * - `AssertionValidationError` is constructed nowhere in `src`: every SAML
 *   refusal is a minted `saml-assertion` error with its rule; the class
 *   itself is deleted;
 * - `quoteUntrusted` is gone: a document value is a diagnostic admitted by
 *   the builder, never quoted into words;
 * - no regular expression runs over document text: the SAMLResponse and
 *   every value read from it are untrusted (the user's rule), so the SAML
 *   path's modules hold no regular expression at all — the DOCTYPE probe,
 *   `xsd:dateTime` and the certificate armour are read as plain characters.
 */

import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, it } from 'node:test';
import { caseTitle } from '../helpers/expectations';
import { SRC } from '../helpers/packagePaths';

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (name === '__tests__') return [];
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return name.endsWith('.ts') ? [path] : [];
  });
}

/** Every line of `src` holding `needle`, as `file:line`. */
function linesWith(needle: string): string[] {
  return sourceFiles(SRC).flatMap((file) =>
    readFileSync(file, 'utf8')
      .split('\n')
      .flatMap((line, i) =>
        line.includes(needle) ? [`${relative(SRC, file)}:${i + 1}`] : [],
      ),
  );
}

describe('the SAML refusals are minted, never the old class', () => {
  it('AssertionValidationError is constructed nowhere in src', () => {
    assert.deepEqual(linesWith('new AssertionValidationError('), []);
  });

  it('quoteUntrusted is gone', () => {
    assert.deepEqual(linesWith('quoteUntrusted'), []);
  });
});

/** The modules that read the SAMLResponse or a value from it. */
const SAML_PATH = [
  'validation/assertionValidator.ts',
  'validation/signedNode.ts',
  'validation/documentIds.ts',
  'validation/xsdDateTime.ts',
  'validation/samlRefusal.ts',
  'auth/samlBearerAssertion.ts',
  'auth/strictXml.ts',
];

/**
 * What a regular expression looks like in these modules: a constructor, or
 * a method that takes or runs one. A literal is caught by its use — every
 * literal is passed to one of these — and by the slash-and-flag shapes.
 */
const REGEX_MARKS = [
  'RegExp',
  '.test(',
  '.exec(',
  '.match(',
  '.matchAll(',
  '.search(',
  '.replace(/',
  '.replaceAll(/',
  '.split(/',
  '/g,',
  '/i.',
  '/u.',
];

describe('no regular expression on the SAML path', () => {
  for (const [caseIndex, caseRow] of SAML_PATH.entries()) {
    const file = caseRow;
    it(caseTitle('%s', caseRow, caseIndex), () => {
      const text = readFileSync(join(SRC, file), 'utf8');
      for (const mark of REGEX_MARKS) {
        assert.deepEqual(
          [file, mark, text.includes(mark)],
          [file, mark, false],
        );
      }
    });
  }
});
