/**
 * The races spec §6b names, run under plain node in a child process with an
 * unhandled-rejection recorder (Jest's own handlers would hide one): the
 * doomed join, a refresh cut after dispatch (real axios, real socket), the
 * drain chain, and the commit order. Each reports what it observed; every
 * one must leave no unhandled rejection behind.
 */

import { describe, expect, it } from '@jest/globals';
import { runPlainNode } from '../helpers/plainNode';

/** Plain-JS helpers every scenario gets. */
const PRELUDE = `
const http = require('node:http');
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const until = async (condition) => { while (!condition()) await turn(); };
// Fixed turns only to observe that nothing more happens, or to let a step
// inside the provider run where it offers no event; every wait FOR something
// is an until() on what the scenario observes.
const settled = async (n = 5) => { for (let i = 0; i < n; i++) await turn(); };
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
const jwt = (sub, seconds = 3600) =>
  b64({ alg: 'none' }) + '.' + b64({ exp: Math.floor(Date.now() / 1000) + seconds, sub }) + '.sig';
const outcomeOf = (promise) => promise.then(
  (value) => ({ value }),
  (error) => ({ kind: errors.readFailure(error, 'unfamiliar-error').kind,
                outcome: errors.readFailure(error, 'unfamiliar-error').facts.outcome }),
);
const silent = { debug() {}, info() {}, warn() {}, error() {} };
class Scripted extends lib.BaseTokenProvider {
  constructor(config) {
    super(config);
    this.logins = [];
    this.refreshes = [];
    if (config.access) { this.authorizationToken = config.access; this.expiresAt = Date.now() - 1; }
    if (config.refresh) this.refreshToken = config.refresh;
  }
  performLogin(attempt) { const d = deferred(); this.logins.push({ attempt, d }); return d.promise; }
  performRefresh(refreshToken, _signal, dispatched) { dispatched(); const d = deferred(); this.refreshes.push({ refreshToken, d }); return d.promise; }
  getAuthType() { return 'authorization_code'; }
  held() { return { access: this.authorizationToken, refresh: this.refreshToken }; }
  expire() { this.expiresAt = Date.now() - 1; }
}
const result = (access, refresh) => ({ authorizationToken: access, refreshToken: refresh, authType: 'authorization_code', expiresIn: 3600 });
`;

describe('the races of spec §6b, under plain node', () => {
  it('the doomed join: a fresh attempt wins, the late login changes nothing', () => {
    const run = runPlainNode<Record<string, unknown>>(`${PRELUDE}
const seen = [];
const p = new Scripted({ renewal: lib.refreshThenLogin(), onTokens: async (r) => { seen.push([r.authorizationToken, r.refreshToken, r.refreshTokenDisposition]); } });
const only = new AbortController();
const doomed = outcomeOf(p.getTokens({ signal: only.signal }));
await until(() => p.logins.length === 1);
only.abort();
const doomedOutcome = await doomed;
const fresh = outcomeOf(p.getTokens());
await until(() => p.logins.length === 2);
p.logins[1].d.resolve(result('T2', 'R2'));
const freshOutcome = await fresh;
p.logins[0].d.resolve(result('T1', 'R1'));
// A rejection of the first login after its waiters left: handled too.
await settled();
report({ doomedOutcome, fresh: freshOutcome.value.authorizationToken, held: p.held(), seen });
`);
    expect(run.stderr).toBe('');
    expect(run.result).toEqual({
      doomedOutcome: { kind: 'interactive-login', outcome: 'aborted' },
      fresh: 'T2',
      held: { access: 'T2', refresh: 'R2' },
      seen: [['T2', 'R2', 'replace']],
    });
    expect(run.unhandled).toEqual([]);
  });

  it('the doomed join, the late login failing: no unhandled rejection', () => {
    const run = runPlainNode<Record<string, unknown>>(`${PRELUDE}
const p = new Scripted({ renewal: lib.refreshThenLogin() });
const only = new AbortController();
const doomed = outcomeOf(p.getTokens({ signal: only.signal }));
await until(() => p.logins.length === 1);
only.abort();
await doomed;
p.logins[0].d.reject(new Error('late failure'));
await settled();
report({ held: p.held() });
`);
    expect(run.result).toEqual({ held: {} });
    expect(run.unhandled).toEqual([]);
  });

  it('a refresh cut after dispatch, on a real socket: R submitted once, the late R2 adopted', () => {
    const run = runPlainNode<Record<string, unknown>>(`${PRELUDE}
const submitted = [];
const held = [];
const server = http.createServer((req, res) => {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const params = new URLSearchParams(body);
    if (params.get('grant_type') === 'refresh_token') {
      submitted.push(params.get('refresh_token'));
      held.push(res);
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ access_token: jwt('login'), refresh_token: 'S' }));
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const url = 'http://127.0.0.1:' + server.address().port;
const seen = [];
const p = new lib.AuthorizationCodeProvider({ renewal: lib.refreshThenLogin(),
  uaaUrl: url, clientId: 'cid', clientSecret: 'sec', logger: silent,
  authorization: { authorize: async () => { throw new Error('no login expected'); } },
  accessToken: jwt('held', -3600), refreshToken: 'R',
  onTokens: async (r) => { seen.push([r.refreshToken, r.refreshTokenDisposition]); },
});
const only = new AbortController();
const cut = outcomeOf(p.getTokens({ signal: only.signal }));
await until(() => held.length === 1);
only.abort();
const cutOutcome = await cut;
await settled();
const stillOpen = !held[0].destroyed && !held[0].writableEnded;
const T2 = jwt('rotated');
held[0].writeHead(200, { 'content-type': 'application/json' });
held[0].end(JSON.stringify({ access_token: T2, refresh_token: 'R2' }));
await until(() => seen.length === 2);
const after = await p.getTokens();
server.close();
report({ cutOutcome, stillOpen, submitted, seen, adopted: after.refreshToken === 'R2' && after.authorizationToken === T2 });
`);
    expect(run.stderr).toBe('');
    expect(run.result).toEqual({
      cutOutcome: { kind: 'interactive-login', outcome: 'aborted' },
      stillOpen: true,
      submitted: ['R'],
      seen: [
        [null, 'clear'],
        ['R2', 'replace'],
      ],
      adopted: true,
    });
    expect(run.unhandled).toEqual([]);
  });

  it('the drain chain: three aborted attempts, the fourth starts only after the first released its socket', () => {
    const run = runPlainNode<Record<string, unknown>>(`${PRELUDE}
const token = http.createServer((req, res) => {
  req.resume();
  req.on('end', () => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ access_token: jwt('login'), refresh_token: 'R' }));
  });
});
await new Promise((resolve) => token.listen(0, '127.0.0.1', resolve));
const probe = http.createServer();
await new Promise((resolve) => probe.listen(0, '127.0.0.1', resolve));
const port = probe.address().port;
await new Promise((resolve) => probe.close(resolve));
const scopes = [];
const factory = async (options, use) => {
  const server = http.createServer((_q, s) => s.end('ok'));
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(options.port, '127.0.0.1', resolve); });
  const outcome = deferred();
  const gate = deferred();
  const onAbort = () => outcome.reject(new Error('aborted'));
  options.signal && options.signal.addEventListener('abort', onAbort, { once: true });
  scopes.push({ deliver: (code) => outcome.resolve(code), gate });
  try {
    return await use({ port: options.port, redirectUri: 'http://localhost:' + options.port + '/callback', waitForResult: () => outcome.promise, fail: (e) => outcome.reject(e) });
  } finally {
    await gate.promise;
    await new Promise((resolve) => server.close(resolve));
  }
};
const failures = [];
let calls = 0;
const inner = new lib.BrowserCallbackStrategy({ port, browser: 'none', openUrl: async () => {}, callbackServer: factory });
const p = new lib.AuthorizationCodeProvider({ renewal: lib.refreshThenLogin(),
  uaaUrl: 'http://127.0.0.1:' + token.address().port, clientId: 'cid', clientSecret: 'sec', logger: silent,
  authorization: { authorize: async (request) => { calls += 1; try { return await inner.authorize(request); } catch (e) { failures.push(String(e && e.message)); throw e; } } },
});
const outcomes = [];
for (let i = 0; i < 3; i++) {
  const c = new AbortController();
  const waiting = outcomeOf(p.getTokens({ signal: c.signal }));
  if (i === 0) await until(() => scopes.length === 1); else await settled();
  c.abort();
  outcomes.push(await waiting);
}
let lastDone = false;
const last = outcomeOf(p.getTokens()).then((o) => { lastDone = true; return o; });
await settled();
const callsBeforeRelease = calls;
scopes[0].gate.resolve();
await until(() => scopes.length === 2 || lastDone);
if (scopes.length === 2) {
  scopes[1].deliver('code');
  scopes[1].gate.resolve();
}
const lastOutcome = await last;
token.close();
report({ outcomes: outcomes.map((o) => o.outcome), callsBeforeRelease, calls, refresh: lastOutcome.value && lastOutcome.value.refreshToken, busy: failures.filter((f) => f.includes('already')) });
`);
    expect(run.stderr).toBe('');
    expect(run.result).toEqual({
      outcomes: ['aborted', 'aborted', 'aborted'],
      callsBeforeRelease: 1,
      calls: 2,
      refresh: 'R',
      busy: [],
    });
    expect(run.unhandled).toEqual([]);
  });

  it('the commit order: one commit at a time, in order, the newest persisted last', () => {
    const run = runPlainNode<Record<string, unknown>>(`${PRELUDE}
const hooks = [];
let active = 0;
let most = 0;
const p = new Scripted({ renewal: lib.refreshThenLogin(), onTokens: async (r) => {
  active += 1; most = Math.max(most, active);
  const done = deferred();
  hooks.push({ access: r.authorizationToken, done });
  await done.promise;
  active -= 1;
} });
const first = new AbortController();
const older = outcomeOf(p.getTokens({ signal: first.signal }));
await until(() => p.logins.length === 1);
p.logins[0].d.resolve(result('T1', 'R1'));
await until(() => hooks.length === 1);
first.abort();
const olderOutcome = await older;
p.expire();
const newer = p.refreshTokens();
await until(() => p.refreshes.length === 1);
p.refreshes[0].d.resolve(result('T2', 'R2'));
await settled();
const beforeRelease = hooks.map((h) => h.access);
hooks[0].done.resolve();
await until(() => hooks.length === 2);
hooks[1].done.resolve();
const latest = await newer;
report({ olderOutcome, beforeRelease, order: hooks.map((h) => h.access), most, latest: latest.authorizationToken, held: p.held() });
`);
    expect(run.stderr).toBe('');
    expect(run.result).toEqual({
      olderOutcome: { kind: 'interactive-login', outcome: 'aborted' },
      beforeRelease: ['T1'],
      order: ['T1', 'T2'],
      most: 1,
      latest: 'T2',
      held: { access: 'T2', refresh: 'R2' },
    });
    expect(run.unhandled).toEqual([]);
  });
});
