/**
 * Rule 1 (spec §8.3): every method of every provider, with every collaborator
 * throwing each hostile value, resolves — never rejects — to an outcome whose
 * refusal, if any, is minted, with no secret of the thrown value in it.
 *
 * The whole matrix (`rule1Scenario.ts`: every provider × every collaborator
 * × each hostile value of §11.1 × thrown or rejected) runs under plain node
 * in a child process against the compiled sources, where an unhandled
 * rejection is recorded rather than hidden by Jest (Task 29). The cases
 * below run the credentials in this process too, as Task 19 started them.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { isMinted, renderDiagnostics } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthProvider,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import ts from 'typescript';
import {
  BasicAuthProvider,
  CertificateAuthProvider,
  SamlAuthProvider,
  TokenAuthProvider,
} from '../../index';
import { minted } from '../helpers/minted';
import { runPlainNode } from '../helpers/plainNode';
import { hostileValues, MARKER, type Rule1Report } from './rule1Scenario';

const logonThrowing = (value: () => unknown): ILogonTarget => ({
  tlsMaterial: () => {
    throw value();
  },
  logonParameters: () => {
    throw value();
  },
});
const requestThrowing = (value: () => unknown): IRequestTarget => ({
  header: () => {
    throw value();
  },
  cookies: () => {
    throw value();
  },
});

/** Every provider of the credentials, with its collaborators throwing `value`. */
function providers(value: () => unknown): Array<[string, IAuthProvider]> {
  return [
    ['basic', new BasicAuthProvider('u', 'p')],
    [
      'certificate',
      new CertificateAuthProvider(
        {
          load: async () => {
            throw value();
          },
        },
        {} as never,
      ),
    ],
    ['saml cookies', new SamlAuthProvider('S=x')],
    ['token fixed', TokenAuthProvider.fixed('t')],
    [
      'token from a refresher',
      TokenAuthProvider.from({
        getToken: async () => {
          throw value();
        },
        refreshToken: async () => {
          throw value();
        },
      }),
    ],
  ];
}

function check(outcome: AuthOutcome) {
  if (!outcome.ok) {
    expect(isMinted(outcome.refusal)).toBe(true);
    const { reason, hint } = outcome.refusal;
    expect(reason).not.toContain(MARKER);
    expect(hint ?? '').not.toContain(MARKER);
    expect(renderDiagnostics(minted(outcome.refusal)) ?? '').not.toContain(
      MARKER,
    );
  }
  expect(JSON.stringify(outcome)).not.toContain(MARKER);
}

describe('rule 1: the credentials, every collaborator throwing', () => {
  for (const [valueName, value] of hostileValues()) {
    it.each(providers(value))(`%s — ${valueName}`, async (_name, provider) => {
      const rejections: IAuthRejectionLike[] = [
        { at: 'request', status: 401, error: value() },
        { at: 'logon', error: { key: 'RFC_LOGON_FAILURE' } },
      ];
      const outcomes: AuthOutcome[] = [
        await provider.prepare(),
        await provider.establish(logonThrowing(value)),
        await provider.authorize(requestThrowing(value)),
      ];
      for (const rejection of rejections) {
        outcomes.push(await provider.rejected(rejection as never));
      }
      for (const outcome of outcomes) check(outcome);
    });
  }
});

type IAuthRejectionLike = {
  at: 'request' | 'logon';
  status?: number;
  error: unknown;
};

describe('rule 1: a grant() that throws or answers a rejecting promise', () => {
  const grants: Array<[string, (value: () => unknown) => unknown]> = [
    [
      'throws',
      (value) => {
        throw value();
      },
    ],
    ['answers a rejecting promise', (value) => Promise.reject(value())],
  ];
  for (const [how, grantOf] of grants) {
    for (const [valueName, value] of hostileValues()) {
      it(`a Basic subclass whose grant() ${how} — ${valueName}`, async () => {
        let calls = 0;
        class Granting extends BasicAuthProvider {
          protected override grant() {
            calls += 1;
            return grantOf(value) as never;
          }
        }
        const p = new Granting('u', 'p');
        const seen: unknown[] = [];
        const listener = (reason: unknown) => seen.push(reason);
        process.on('unhandledRejection', listener);
        const outcomes: AuthOutcome[] = [];
        try {
          outcomes.push(await p.prepare());
          outcomes.push(await p.establish(logonThrowing(value)));
          outcomes.push(await p.authorize(requestThrowing(value)));
          outcomes.push(
            await p.rejected({ at: 'request', status: 401, error: {} }),
          );
          await new Promise((resolve) => setTimeout(resolve, 20));
        } finally {
          process.off('unhandledRejection', listener);
        }
        expect(seen).toEqual([]);
        expect(calls).toBe(4);
        for (const outcome of outcomes) check(outcome);
      });
    }
  }
});

/** The collaborators §8.3 names, each at least once in the matrix. */
const SPEC_COLLABORATORS = [
  'interactive strategy',
  'client authentication',
  'client authentication tlsMaterial',
  'certificate loader',
  'device-code presenter',
  'assertion validator',
  'replay store',
  'onTokens',
  'browser launcher',
  'snc locator',
  'snc probe',
  'logger',
  'logon target',
  'request target',
  'token refresher getToken',
  'token refresher refreshToken',
];

/** Every provider this package exports. */
const PROVIDERS = [
  'BasicAuthProvider',
  'CertificateAuthProvider',
  'SamlAuthProvider',
  'TokenAuthProvider.fixed',
  'TokenAuthProvider.from',
  'SncLogonProvider',
  'ClientCredentialsProvider',
  'AuthorizationCodeProvider',
  'OidcBrowserProvider',
  'OidcDeviceFlowProvider',
  'OidcPasswordProvider',
  'OidcTokenExchangeProvider',
  'Saml2BearerProvider',
  'Saml2PureProvider',
  'UaaPasscodeProvider',
];

describe('rule 1: the whole matrix, under plain node against the compiled sources', () => {
  it('every provider × collaborator × hostile value, thrown or rejected: resolves, minted, no marker, no unhandled rejection', () => {
    const dir = mkdtempSync(join(tmpdir(), 'auth-providers-rule1-'));
    try {
      const scenario = join(dir, 'rule1Scenario.js');
      writeFileSync(
        scenario,
        ts.transpileModule(
          readFileSync(join(__dirname, 'rule1Scenario.ts'), 'utf8'),
          {
            compilerOptions: {
              module: ts.ModuleKind.CommonJS,
              target: ts.ScriptTarget.ES2022,
              esModuleInterop: true,
            },
          },
        ).outputText,
      );
      const fixtures = join(__dirname, '..', 'fixtures');
      const run = runPlainNode<Rule1Report>(`
const scenario = require(${JSON.stringify(scenario)});
report(await scenario.run(lib, errors, require('@mcp-abap-adt/auth-mocks'), ${JSON.stringify(fixtures)}));
`);
      expect(run.unhandled).toEqual([]);
      expect(run.result.failures).toEqual([]);
      const providers = new Set(
        run.result.combinations.map((c) => c.split(' · ')[0]),
      );
      expect([...providers].sort()).toEqual([...PROVIDERS].sort());
      const collaborators = new Set(
        run.result.combinations.map((c) => c.split(' · ')[1]),
      );
      for (const name of SPEC_COLLABORATORS) {
        expect([name, collaborators.has(name)]).toEqual([name, true]);
      }
      // Not vacuous: every combination, value, mode and method was checked.
      expect(run.result.combinations.length).toBeGreaterThan(80);
      expect(run.result.checks).toBeGreaterThan(20_000);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 600_000);
});
