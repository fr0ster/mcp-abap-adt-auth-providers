/**
 * An answer typed `void` is ignored, not adopted: a request target's
 * `header()` / `cookies()`, a renewal strategy's `aborted()` and a logger's
 * methods return nothing by contract, so whatever they hand back is never
 * followed — its `then` is never called — and the moment's outcome is what
 * it would be without it. A throw is still handled.
 */

import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { describe, expect, it } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  IRenewalStrategy,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { announcer } from '../../auth/announce';
import { passwordGrant } from '../../auth/oidcToken';
import { logQuietly } from '../../auth/tokenRequest';
import { BasicAuthProvider } from '../../credentials/BasicAuthProvider';
import { SamlAuthProvider } from '../../credentials/SamlAuthProvider';
import { TokenAuthProvider } from '../../credentials/TokenAuthProvider';
import { refreshThenLogin } from '../../renewal';
import { SpnegoAuthProvider } from '../../spnego/SpnegoAuthProvider';
import { jwt, quiet, rejectionOf } from '../helpers/attemptHarness';
import { ScriptedProvider } from '../helpers/scriptedProvider';
import { b64, gssKerberos, OID_KRB5 } from '../spnego/fixtures/derParts';

/** A thenable that never settles and counts every `then` call. */
function neverSettling() {
  const state = { thenCalls: 0 };
  const answer = {
    // biome-ignore lint/suspicious/noThenProperty: a promise library's then is the point
    then() {
      state.thenCalls += 1;
    },
  };
  return { answer, state };
}

describe('a request target answering a thenable', () => {
  it('header() of a Basic credential: ok, then never called', async () => {
    const { answer, state } = neverSettling();
    const target = {
      header: () => answer,
      cookies: () => undefined,
    } as unknown as IRequestTarget;
    expect(await new BasicAuthProvider('u', 'p').authorize(target)).toEqual({
      ok: true,
    });
    expect(state.thenCalls).toBe(0);
  });

  it('header() of a fixed token: ok, then never called', async () => {
    const { answer, state } = neverSettling();
    const target = {
      header: () => answer,
      cookies: () => undefined,
    } as unknown as IRequestTarget;
    expect(
      await TokenAuthProvider.fixed(jwt('held', 3600)).authorize(target),
    ).toEqual({ ok: true });
    expect(state.thenCalls).toBe(0);
  });

  it('cookies() of a SAML session: ok, then never called', async () => {
    const { answer, state } = neverSettling();
    const target = {
      header: () => undefined,
      cookies: () => answer,
    } as unknown as IRequestTarget;
    expect(await new SamlAuthProvider('MYSAPSSO2=x').authorize(target)).toEqual(
      { ok: true },
    );
    expect(state.thenCalls).toBe(0);
  });

  it('header() of SPNego: ok, then never called', async () => {
    const { answer, state } = neverSettling();
    const target = {
      header: () => answer,
      cookies: () => undefined,
    } as unknown as IRequestTarget;
    const kerberos = b64(gssKerberos(OID_KRB5, 64));
    const provider = new SpnegoAuthProvider({
      servicePrincipal: 'HTTP@host.example',
      tokenSource: {
        token: async () => ({ ok: true, token: kerberos }),
      } as never,
    });
    expect(await provider.authorize(target)).toEqual({ ok: true });
    expect(state.thenCalls).toBe(0);
  });

  it('a target whose header() throws is still answered Oops', async () => {
    const target = {
      header: () => {
        throw new Error('wire broke');
      },
      cookies: () => undefined,
    } as unknown as IRequestTarget;
    const outcome = await new BasicAuthProvider('u', 'p').authorize(target);
    expect(outcome.ok).toBe(false);
  });
});

describe('a renewal strategy whose aborted() answers a thenable', () => {
  it('the abort ends the renewal as before, then never called', async () => {
    const { answer, state } = neverSettling();
    const strategy: IRenewalStrategy = {
      next: (situation) => refreshThenLogin().next(situation),
      aborted: () => answer as never,
    };
    const provider = new ScriptedProvider({
      renewal: strategy,
      accessToken: jwt('held', -3600),
      refreshToken: 'R',
    });
    const only = new AbortController();
    const cut = rejectionOf(provider.getTokens({ signal: only.signal }));
    await provider.refreshes.nth(1);
    only.abort();
    const failure = readFailure(await cut, 'unfamiliar-error');
    expect(failure.facts).toMatchObject({ outcome: 'aborted' });
    await quiet();
    expect(state.thenCalls).toBe(0);
  });
});

describe('a logger answering a thenable', () => {
  it('logQuietly does not follow the answer of info()', async () => {
    const { answer, state } = neverSettling();
    const logger = { info: () => answer } as unknown as ILogger;
    logQuietly(() => logger.info('line'));
    await quiet();
    expect(state.thenCalls).toBe(0);
  });

  it('announcer: the prompt is not copied to stderr and then is never called', async () => {
    const { answer, state } = neverSettling();
    const written: string[] = [];
    const realWrite = process.stderr.write;
    process.stderr.write = ((chunk: unknown) => {
      written.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;
    try {
      announcer({ info: () => answer } as unknown as ILogger)('prompt');
      await quiet();
    } finally {
      process.stderr.write = realWrite;
    }
    expect(state.thenCalls).toBe(0);
    expect(written).toEqual([]);
  });

  it('a throwing logger on a token-site failure: the site throws its own failure', async () => {
    const server = createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_grant' }));
      });
    });
    await new Promise<void>((resolve) =>
      server.listen(0, '127.0.0.1', resolve),
    );
    const { port } = server.address() as AddressInfo;
    const boom = () => {
      throw new Error('logger SECRET');
    };
    const logger = {
      debug: boom,
      info: boom,
      warn: boom,
      error: boom,
    } as ILogger;
    try {
      for (const authDebug of [false, true]) {
        const thrown = await passwordGrant(
          `http://127.0.0.1:${port}/token`,
          'cid',
          'sec',
          'u',
          'p',
          undefined,
          logger,
          undefined,
          { authDebug },
        ).then(
          () => undefined,
          (error: unknown) => error,
        );
        const failure = readFailure(thrown, 'unfamiliar-error');
        expect(failure.kind).toBe('request-failed');
        expect(JSON.stringify(failure.reason)).not.toContain('SECRET');
      }
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  });
});
