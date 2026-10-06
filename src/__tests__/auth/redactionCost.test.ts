/**
 * The redaction path is linear (review fix rounds 2 and 3): every regex of
 * `oauthErrorBody.ts`, each with the input that is worst for it, at about
 * 1 MB, redacts in well under 2 s — a bound measured here, never a timer in
 * the code, and nothing is cut before redaction. The table in the task-20
 * report lists each regex against its case.
 */

import { describe, expect, it } from '@jest/globals';
import { oauthErrorFields } from '../../auth/oauthErrorBody';

const MB = 1_000_000;
const times = (unit: string): string =>
  unit.repeat(Math.ceil(MB / unit.length));

const JWT = `eyJhbGciOiJSUzI1NiJ9.${'eyJzdWIiOiJ1c2VyIn0'.repeat(10)}.c2lnbmF0dXJl`;
const SECRETS = [
  'se+cr%25et/x-0123456789-client',
  'pass word with spaces',
  JWT,
  Buffer.from('client:se+cr%25et/x-0123456789-client').toString('base64'),
];

const CASES: [regex: string, input: string, text: string][] = [
  ['AROUND / BREAK', 'a + spaces + b', `a${' '.repeat(MB)}b`],
  ['AROUND / BREAK', 'a + tabs + b', `a${'\t'.repeat(MB)}b`],
  ['AROUND / BREAK', 'a + CRLF + b', `a${times('\r\n')}b`],
  ['AROUND / BREAK', 'a + %20 + b', `a${times('%20')}b`],
  ['AROUND / BREAK', 'a + %250A + b', `a${times('%250A')}b`],
  ['BASE64_RUN', 'one base64 run', 'A'.repeat(MB)],
  ['BASE64_RUN', 'base64 pieces split by spaces', times('QUJDRA ')],
  ['BASE64_RUN', 'escaped base64 characters', times('%41')],
  ['BASE64_RUN', 'padding only', '='.repeat(MB)],
  ['JWT shape', 'eyJ repeated, no dot', times('eyJ')],
  ['JWT shape', 'eyJa. repeated (one dot each)', times('eyJa.')],
  ['JWT shape', 'eyJa.b repeated', times('eyJa.b')],
  ['JWT shape', 'dots only', '.'.repeat(MB)],
  ['JWT shape', 'a. repeated (many segments, no eyJ)', times('a.')],
  [
    'ESCAPE_RUN / ANY_DEPTH_ESCAPE',
    '%2525…2541 chain',
    `%${'25'.repeat(MB / 2)}41`,
  ],
  ['ESCAPE_RUN / ANY_DEPTH_ESCAPE', '%25 repeated', times('%25')],
  ['ESCAPE_RUN / ANY_DEPTH_ESCAPE', '%%32B nested', times('%%32B')],
  ['ESCAPE_RUN / ANY_DEPTH_ESCAPE', 'percent signs only', '%'.repeat(MB)],
  [
    'known-secret pattern',
    'a secret prefix then whitespace',
    `se+cr${' '.repeat(MB)}x`,
  ],
  [
    'known-secret pattern',
    'a secret prefix then escaped whitespace',
    `se+cr${times('%2520')}x`,
  ],
  [
    'known-secret pattern',
    'a value with spaces, then spaces',
    `pass${' '.repeat(MB)}word`,
  ],
  [
    'known-secret pattern',
    'near misses of the secret',
    times('se+cr%25et/x-0123456789-clien '),
  ],
  [
    'known-secret pattern',
    'a %25 chain inside the secret',
    `se+cr%${'25'.repeat(MB / 2)}et`,
  ],
  [
    'known-secret pattern',
    'the JWT head repeated',
    times('eyJhbGciOiJSUzI1NiJ9.'),
  ],
  ['WRAPPING / fail-closed', 'whitespace between escapes', times('%2 \r\n')],
  [
    'capped / previews',
    'the secret repeated',
    times('se+cr%25et/x-0123456789-client '),
  ],
];

describe('the redaction path is linear', () => {
  it.each(CASES)('%s: %s (1 MB) in well under 2 s', (_regex, _input, text) => {
    const started = performance.now();
    for (const field of ['error_description', 'error_uri'] as const) {
      oauthErrorFields({ [field]: text }, SECRETS);
    }
    expect(performance.now() - started).toBeLessThan(2_000);
  });
});
