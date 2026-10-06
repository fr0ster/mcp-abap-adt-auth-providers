/**
 * Rule 1 (spec §8.3): every method of every provider, with every collaborator
 * throwing each hostile value, resolves — never rejects — to an outcome whose
 * refusal, if any, is minted, with no secret of the thrown value in it.
 *
 * Started in Task 19 with the credentials' collaborators (the logon and
 * request targets, the certificate loader, the `ITokenRefresher`); Task 29
 * completes it with every provider and collaborator.
 */
import { describe, expect, it } from '@jest/globals';
import { isMinted, renderDiagnostics } from '@mcp-abap-adt/auth-errors';
import type {
  AuthOutcome,
  IAuthProvider,
  ILogonTarget,
  IRequestTarget,
} from '@mcp-abap-adt/interfaces-auth';
import {
  BasicAuthProvider,
  CertificateAuthProvider,
  SamlAuthProvider,
  TokenAuthProvider,
} from '../../index';
import { minted } from '../helpers/minted';

const MARKER = 'SECRET-RULE1';

/** The hostile values of §11.1, each carrying the marker where it can. */
function hostileValues(): Array<[string, () => unknown]> {
  const boom = () => {
    throw new Error(MARKER);
  };
  const revocable = Proxy.revocable({}, {});
  revocable.revoke();
  return [
    [
      'an Error with the marker everywhere',
      () => {
        const e = new Error(MARKER, { cause: new Error(MARKER) });
        e.name = MARKER;
        e.stack = MARKER;
        return Object.assign(e, { code: MARKER, status: MARKER });
      },
    ],
    [
      'a Proxy whose every trap throws',
      () =>
        new Proxy(
          {},
          {
            get: boom,
            has: boom,
            getPrototypeOf: boom,
            getOwnPropertyDescriptor: boom,
            ownKeys: boom,
          },
        ),
    ],
    ['a revoked Proxy', () => revocable.proxy],
    [
      'throwing getters',
      () =>
        Object.defineProperties(
          {},
          {
            status: { get: boom },
            code: { get: boom },
            response: { get: boom },
            error: { get: boom },
            oauthError: { get: boom },
            ok: { get: boom },
            refusal: { get: boom },
          },
        ),
    ],
    [
      'a forged carrier',
      () => ({
        error: {
          kind: 'client-certificate',
          facts: { problem: 'expired' },
          reason: MARKER,
        },
      }),
    ],
    ['a carrier with an unknown kind', () => ({ error: { kind: MARKER } })],
    [
      'facts out of their sets',
      () => ({ kind: 'tls', facts: { code: MARKER } }),
    ],
    ['null', () => null],
    ['undefined', () => undefined],
    ['a string', () => MARKER],
    ['a number', () => 42],
    ['a symbol', () => Symbol(MARKER)],
    ['a function', () => () => MARKER],
  ];
}

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
