/**
 * A consumer's async logger — every method answers a rejecting promise —
 * on a token site's paths (controller addition after Task 22): `logQuietly`
 * attaches a no-op rejection handler to a plain native promise, so no
 * `unhandledRejection` arrives. Run under plain node in a child process,
 * where an unhandled rejection is recorded rather than hidden by Jest.
 */

import { describe, expect, it } from '@jest/globals';
import { runPlainNode } from '../helpers/plainNode';

const scenario = (logger: string) => `
const http = require('node:http');
const server = http.createServer((req, res) => {
  req.resume();
  req.on('end', () => {
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'invalid_grant' }));
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const { port } = server.address();
const logger = ${logger};
const { passwordGrant } = load('auth/oidcToken.js');
const outcomes = [];
for (const authDebug of [false, true]) {
  try {
    await passwordGrant('http://127.0.0.1:' + port + '/token', 'cid', 'sec', 'u', 'p', undefined, logger, undefined, { authDebug });
    outcomes.push('resolved');
  } catch (error) {
    outcomes.push(errors.readFailure(error, 'unfamiliar-error').kind);
  }
}
server.close();
report(outcomes);
`;

describe('an async logger on a token site', () => {
  it('a rejecting promise from every logger method leaves no unhandled rejection', () => {
    const run = runPlainNode<string[]>(
      scenario(`{
        debug: async () => { throw new Error('async debug'); },
        info: async () => { throw new Error('async info'); },
        warn: async () => { throw new Error('async warn'); },
        error: async () => { throw new Error('async error'); },
      }`),
    );
    expect(run.stderr).toBe('');
    expect(run.result).toEqual(['request-failed', 'request-failed']);
    expect(run.unhandled).toEqual([]);
  });

  it('a foreign thenable is never called: its then does not run', () => {
    const run = runPlainNode<string[]>(
      scenario(`{
        debug: () => ({ then() { throw new Error('then ran'); } }),
        info: () => ({ then() { throw new Error('then ran'); } }),
        warn: () => undefined,
        error: () => undefined,
      }`),
    );
    expect(run.result).toEqual(['request-failed', 'request-failed']);
    expect(run.unhandled).toEqual([]);
  });
});

const codeExchange = (logger: string, answer: 'token' | 'refused-port') => `
const http = require('node:http');
const server = http.createServer((req, res) => {
  req.resume();
  req.on('end', () => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ access_token: 'at', refresh_token: 'rt' }));
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const { port } = server.address();
if (${JSON.stringify(answer)} === 'refused-port') {
  await new Promise((resolve) => server.close(resolve));
}
const logger = ${logger};
const { exchangeCodeForToken } = load('auth/browserAuth.js');
let outcome;
try {
  const tokens = await exchangeCodeForToken(
    { uaaUrl: 'http://127.0.0.1:' + port, uaaClientId: 'cid', uaaClientSecret: 'sec' },
    'code', 'http://localhost:61001/callback', logger,
  );
  outcome = { resolved: tokens.accessToken };
} catch (error) {
  const read = errors.readFailure(error, 'unfamiliar-error');
  outcome = { kind: read.kind, problem: read.facts.problem };
}
if (${JSON.stringify(answer)} === 'token') server.close();
report(outcome);
`;

describe('the UAA code exchange with a consumer logger', () => {
  it('an async logger: a successful exchange leaves no unhandled rejection', () => {
    const run = runPlainNode<Record<string, unknown>>(
      codeExchange(
        `{
          debug: async () => { throw new Error('async debug'); },
          info: async () => { throw new Error('async info'); },
          warn: async () => { throw new Error('async warn'); },
          error: async () => { throw new Error('async error'); },
        }`,
        'token',
      ),
    );
    expect(run.stderr).toBe('');
    expect(run.result).toEqual({ resolved: 'at' });
    expect(run.unhandled).toEqual([]);
  });

  it('a throwing logger: a refused connection stays request-failed, not unknown', () => {
    const run = runPlainNode<Record<string, unknown>>(
      codeExchange(
        `{
          debug: () => { throw new Error('debug threw'); },
          info: () => { throw new Error('info threw'); },
          warn: () => { throw new Error('warn threw'); },
          error: () => { throw new Error('error threw'); },
        }`,
        'refused-port',
      ),
    );
    expect(run.result).toEqual({
      kind: 'request-failed',
      problem: 'no-response',
    });
    expect(run.unhandled).toEqual([]);
  });
});
