/**
 * A collaborator's answer is the consumer's own code, awaited normally
 * inside the guarded boundary (the user's decision, 2026-10-07): a
 * Promises/A+ promise from another library (Bluebird, Q, …) must work.
 *
 * For each collaborator below, answered as an `APlusPromise`:
 * - resolving → the value is used, the moment answers Ok;
 * - rejecting → a classified failure (a minted refusal);
 * - its `then` throwing → a classified failure;
 * - never settling → bounded by the consumer's own `AbortSignal`, where the
 *   provider takes one.
 * And no `unhandledRejection` anywhere.
 */

import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { isMinted } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthProvider,
  ICertificateMaterial,
} from '@mcp-abap-adt/interfaces-auth';
import {
  CertificateAuthProvider,
  ClientCredentialsProvider,
  SncLogonProvider,
  TokenAuthProvider,
  UaaPasscodeProvider,
} from '../../index';
import { refreshThenLogin } from '../../renewal';
import { APlusPromise } from '../helpers/aplusPromise';
import { recordingTargets } from '../helpers/targets';

const certificate: ICertificateMaterial = {
  cert: readFileSync(
    join(__dirname, '..', 'fixtures', 'certificates', 'client.crt'),
  ),
  key: readFileSync(
    join(__dirname, '..', 'fixtures', 'certificates', 'client.key'),
  ),
};

const b64url = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString('base64url');
const accessToken = () =>
  `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url({
    exp: Math.floor(Date.now() / 1000) + 3600,
    jti: Math.random().toString(36).slice(2),
  })}.sig`;

let server: Server;
let base: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, {
        'content-type': 'application/json',
        connection: 'close',
      });
      res.end(
        JSON.stringify({
          access_token: accessToken(),
          refresh_token: `rt-${Math.random().toString(36).slice(2)}`,
          token_type: 'bearer',
          expires_in: 3600,
        }),
      );
    });
  });
  await new Promise<void>((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve()),
  );
  const address = server.address();
  base = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
});

type Answer = 'resolving' | 'rejecting' | 'then throwing' | 'never settling';

/** The collaborator's answer: `value` as an APlusPromise, shaped by `how`. */
function answer(how: Answer, value: unknown): unknown {
  switch (how) {
    case 'resolving':
      return APlusPromise.resolve(value);
    case 'rejecting':
      return APlusPromise.reject(new Error('collaborator failed: SECRET-A+'));
    case 'then throwing':
      return {
        // biome-ignore lint/suspicious/noThenProperty: a thenable whose then throws
        then() {
          APlusPromise.thenCalls += 1;
          throw new Error('then threw: SECRET-A+');
        },
      };
    case 'never settling':
      return APlusPromise.never();
  }
}

interface Row {
  readonly name: string;
  /** The provider, with `how` wired into the one collaborator. */
  readonly make: (how: Answer, signal?: AbortSignal) => IAuthProvider;
  /** The moment that reads the collaborator. */
  readonly moment: 'prepare' | 'authorize';
  /** Whether the provider takes a consumer's AbortSignal. */
  readonly signalled: boolean;
  /**
   * The collaborator's failure is best effort by contract — an SNC product
   * probe (logged, the library stands) — so the moment stays Ok. (A
   * persistence strategy's awaited report is not: its failure is the
   * renewal's, spec §6c.6.)
   */
  readonly failureStands?: boolean;
}

const ROWS: Row[] = [
  {
    name: 'ClientCredentialsProvider · client authentication',
    moment: 'authorize',
    signalled: true,
    make: (how, signal) =>
      new ClientCredentialsProvider({
        renewal: refreshThenLogin(),
        uaaUrl: base,
        clientId: 'cid',
        clientAuthentication: {
          authenticate: (draft: { clientId: string }) =>
            answer(how, { parameters: { client_id: draft.clientId } }),
        } as never,
        ...(signal ? { signal } : {}),
      }),
  },
  {
    name: 'ClientCredentialsProvider · persistence report',
    moment: 'authorize',
    signalled: true,
    make: (how, signal) =>
      new ClientCredentialsProvider({
        renewal: refreshThenLogin(),
        uaaUrl: base,
        clientId: 'cid',
        clientSecret: 's',
        persistence: { report: () => answer(how, undefined) as never },
        ...(signal ? { signal } : {}),
      }),
  },
  {
    name: 'UaaPasscodeProvider · interactive strategy',
    moment: 'authorize',
    signalled: true,
    make: (how, signal) =>
      new UaaPasscodeProvider({
        renewal: refreshThenLogin(),
        uaaUrl: base,
        clientId: 'cid',
        clientSecret: 's',
        authorization: {
          authorize: () =>
            answer(how, {
              payload: 'passcode',
              redirectUri: 'urn:passcode',
            }) as never,
        },
        ...(signal ? { signal } : {}),
      }),
  },
  {
    name: 'CertificateAuthProvider · certificate loader',
    moment: 'prepare',
    signalled: false,
    make: (how) =>
      new CertificateAuthProvider(
        { load: () => answer(how, { ...certificate }) as never },
        {} as never,
      ),
  },
  {
    name: 'TokenAuthProvider.from · token refresher',
    moment: 'authorize',
    signalled: false,
    make: (how) =>
      TokenAuthProvider.from({
        getToken: () => answer(how, 'the-token') as never,
        refreshToken: () => answer(how, 'another-token') as never,
      }),
  },
  {
    name: 'SncLogonProvider · locator',
    moment: 'prepare',
    signalled: true,
    make: (how, signal) =>
      new SncLogonProvider({
        partnerName: 'p:CN=SID',
        locator: {
          locate: () =>
            answer(how, {
              path: 'C:\\sap\\sapcrypto.dll',
              archs: ['x64'],
            }) as never,
        },
        probes: [],
        ...(signal ? { signal } : {}),
      }),
  },
  {
    name: 'SncLogonProvider · product probe',
    moment: 'prepare',
    signalled: true,
    // A probe only names the product for a hint: its failure is logged (H5)
    // and the library stands.
    failureStands: true,
    make: (how, signal) =>
      new SncLogonProvider({
        partnerName: 'p:CN=SID',
        locator: {
          locate: async () => ({
            path: 'C:\\sap\\sapcrypto.dll',
            archs: ['x64'],
          }),
        },
        probes: [
          {
            product: 'probe',
            appliesTo: () => answer(how, true) as never,
          },
        ],
        ...(signal ? { signal } : {}),
      }),
  },
];

/** Runs `moment` on `provider`, recording `unhandledRejection` meanwhile. */
async function run(
  row: Row,
  provider: IAuthProvider,
): Promise<{ outcome: AuthOutcome; unhandled: unknown[]; headers: object }> {
  const unhandled: unknown[] = [];
  const listener = (reason: unknown) => unhandled.push(reason);
  process.on('unhandledRejection', listener);
  try {
    const { requestTarget, request } = recordingTargets();
    const outcome =
      row.moment === 'prepare'
        ? await provider.prepare()
        : await provider.authorize(requestTarget);
    await new Promise((resolve) => setTimeout(resolve, 20));
    return { outcome, unhandled, headers: request.headers };
  } finally {
    process.off('unhandledRejection', listener);
  }
}

describe('a collaborator answering a Promises/A+ promise', () => {
  describe.each(ROWS.map((row) => [row.name, row] as const))(
    '%s',
    (_name, row) => {
      it('resolving: the answer is followed and used — Ok', async () => {
        APlusPromise.thenCalls = 0;
        const { outcome, unhandled, headers } = await run(
          row,
          row.make('resolving'),
        );
        expect(outcome).toEqual({ ok: true });
        expect(APlusPromise.thenCalls).toBeGreaterThan(0);
        if (row.moment === 'authorize')
          expect(Object.keys(headers)).toContain('Authorization');
        expect(unhandled).toEqual([]);
      });

      it.each(['rejecting', 'then throwing'] as const)(
        '%s: a classified failure, no secret, no unhandled rejection',
        async (how) => {
          APlusPromise.thenCalls = 0;
          const { outcome, unhandled } = await run(row, row.make(how));
          expect(APlusPromise.thenCalls).toBeGreaterThan(0);
          expect(unhandled).toEqual([]);
          if (row.failureStands) {
            expect(outcome).toEqual({ ok: true });
            return;
          }
          expect(outcome.ok).toBe(false);
          if (outcome.ok) return;
          expect(isMinted(outcome.refusal)).toBe(true);
          expect(JSON.stringify(outcome)).not.toContain('SECRET-A+');
          expect(APlusPromise.thenCalls).toBeGreaterThan(0);
          expect(unhandled).toEqual([]);
        },
      );

      if (row.signalled) {
        it('never settling: bounded by the consumer’s AbortSignal', async () => {
          const { outcome, unhandled } = await run(
            row,
            row.make('never settling', AbortSignal.timeout(200)),
          );
          expect(outcome.ok).toBe(false);
          if (outcome.ok) return;
          expect(isMinted(outcome.refusal)).toBe(true);
          expect(outcome.refusal).toMatchObject({
            kind: 'interactive-login',
            facts: { outcome: 'aborted' },
          });
          expect(unhandled).toEqual([]);
        }, 10_000);
      }
    },
  );
});
