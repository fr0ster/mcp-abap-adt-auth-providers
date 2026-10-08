/**
 * The shipped protocols' judges, per protocol and per `via`;
 * a parameter counts only when present exactly once; a bare
 * paste only without `? & = / #`, a pasted URL must carry the expected
 * `state`. Also the protocol's rows of Form, and Logs: no code,
 * `state`, pasted text or `SAMLResponse` in a verdict's error or a thrown
 * one.
 */

import { describe, expect, it } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  ANSWER_REFUSALS,
  AnswerJudge,
  AnswerVerdict,
  AuthorizationAnswer,
  IAuthorizationProtocol,
} from '@mcp-abap-adt/interfaces-auth';
import {
  oauthCode,
  oidcCode,
  passcode,
  samlResponse,
} from '../../authorization/protocol';
import { configurationOf, thrownFrom } from '../helpers/minted';

const STATE = 'the-expected-state-AbCdEf0123456789_-xyzXYZ';
const OTHER = 'a-state-from-another-login-0123456789abcdef';
const CODE = 'the-code-9f8e7d';
const URL_WITH_STATE = `https://uaa.example/oauth/authorize?client_id=cid&response_type=code&state=${STATE}`;

const redirect = (
  query: string,
  method: 'GET' | 'POST' = 'GET',
): AuthorizationAnswer => ({
  via: 'redirect',
  method,
  params: new URLSearchParams(query),
});
const text = (
  via: 'form' | 'terminal' | 'consumer',
  value: string,
): AuthorizationAnswer => ({ via, text: value });

/** Every secret a test hands a judge: none may reach an error. */
const SECRETS = [STATE, OTHER, CODE, 'PHNhbWw+', 'PASSCODE-77', 'desc-text'];

/** The error of an `end` verdict, checked to carry nothing of the input. */
function endError<T>(verdict: AnswerVerdict<T>) {
  expect(verdict.verdict).toBe('end');
  if (verdict.verdict !== 'end') throw new Error('not an end');
  const rendered = JSON.stringify(verdict.error) + String(verdict.error.reason);
  for (const secret of SECRETS) expect(rendered).not.toContain(secret);
  return verdict.error;
}

const refused = (reason: (typeof ANSWER_REFUSALS)[number]) => ({
  verdict: 'refuse',
  reason,
});

/** The two code protocols, each with the payload it accepts for a code. */
const CODE_PROTOCOLS: ReadonlyArray<
  [
    string,
    () => IAuthorizationProtocol<unknown>,
    (code: string, via: AuthorizationAnswer['via']) => unknown,
  ]
> = [
  ['oauthCode', oauthCode, (code) => code],
  [
    'oidcCode',
    oidcCode,
    (code, via) => ({
      code,
      state: via === 'redirect' ? STATE : undefined,
    }),
  ],
];

describe.each(CODE_PROTOCOLS)('%s', (_name, make, payloadOf) => {
  const judge = (): AnswerJudge<unknown> => make().begin(URL_WITH_STATE);

  it('takes a redirect by GET and has paste words', () => {
    const protocol = make();
    expect(protocol.redirect).toBe('required');
    expect(protocol.callbackMethods).toEqual(['GET']);
    expect(protocol.paste?.prompt).toEqual(expect.any(String));
    expect(protocol.paste?.instructions).toEqual(expect.any(String));
  });

  describe('begin: the URL must carry exactly one state (C7)', () => {
    it.each([
      ['a URL that does not parse', 'not a url'],
      ['a URL without state', 'https://uaa.example/oauth/authorize?a=1'],
      [
        'a URL with two states',
        `https://uaa.example/authorize?state=${STATE}&state=${STATE}`,
      ],
      ['a URL with an empty state', 'https://uaa.example/authorize?state='],
    ])('%s → configuration invalid-value authorizationUrl', async (_c, url) => {
      const thrown = await thrownFrom(() => make().begin(url));
      expect(configurationOf(thrown)).toMatchObject({
        case: 'invalid-value',
        fields: ['authorizationUrl'],
      });
      const rendered = JSON.stringify(readFailure(thrown, 'unfamiliar-error'));
      expect(rendered).not.toContain(STATE);
      expect(rendered).not.toContain('uaa.example');
    });
  });

  describe('redirect: the binding first', () => {
    it.each([
      ['no state', `code=${CODE}`],
      [
        'two states, both the expected one',
        `state=${STATE}&state=${STATE}&code=${CODE}`,
      ],
      ['a wrong state', `state=${OTHER}&code=${CODE}`],
      ['an empty state', `state=&code=${CODE}`],
      [
        'a forged error with a wrong state',
        `state=${OTHER}&error=access_denied`,
      ],
      ['a forged error with no state', 'error=access_denied'],
    ])('%s → refuse state', (_c, query) => {
      expect(judge()(redirect(query))).toEqual(refused('state'));
    });

    it('none, two, a wrong and then the right state: refused thrice, then accepted', () => {
      const once = judge();
      expect(once(redirect(`code=${CODE}`))).toEqual(refused('state'));
      expect(
        once(redirect(`state=${STATE}&state=${OTHER}&code=${CODE}`)),
      ).toEqual(refused('state'));
      expect(once(redirect(`state=${OTHER}&code=${CODE}`))).toEqual(
        refused('state'),
      );
      expect(once(redirect(`state=${STATE}&code=${CODE}`))).toEqual({
        verdict: 'accept',
        payload: payloadOf(CODE, 'redirect'),
      });
    });

    it.each(['GET', 'POST'] as const)(
      'the right state and one code by %s → accept',
      (method) => {
        expect(
          judge()(redirect(`state=${STATE}&code=${CODE}`, method)),
        ).toEqual({
          verdict: 'accept',
          payload: payloadOf(CODE, 'redirect'),
        });
      },
    );

    it.each([
      ['no code', `state=${STATE}`],
      ['two codes', `state=${STATE}&code=${CODE}&code=${CODE}`],
      ['an empty code', `state=${STATE}&code=`],
    ])('the right state and %s → refuse no-payload', (_c, query) => {
      expect(judge()(redirect(query))).toEqual(refused('no-payload'));
    });

    it('the right state and a registered error → end identity-provider-refused, shown for the page only', () => {
      const verdict = judge()(
        redirect(
          `state=${STATE}&error=access_denied&error_description=desc-text&code=${CODE}`,
        ),
      );
      const error = endError(verdict);
      expect(error).toMatchObject({
        kind: 'interactive-login',
        facts: {
          outcome: 'identity-provider-refused',
          oauthError: 'access_denied',
        },
      });
      expect(verdict).toMatchObject({ shown: 'access_denied: desc-text' });
    });

    it('an unregistered error is kept out of the facts, and shown alone without a description', () => {
      const verdict = judge()(redirect(`state=${STATE}&error=made_up_code`));
      const error = endError(verdict);
      expect(error.kind).toBe('interactive-login');
      expect(error.facts).toEqual({ outcome: 'identity-provider-refused' });
      expect(verdict).toMatchObject({ shown: 'made_up_code' });
      expect(JSON.stringify(error)).not.toContain('made_up_code');
    });

    it('two errors are no error: the code decides', () => {
      expect(
        judge()(
          redirect(`state=${STATE}&error=access_denied&error=access_denied`),
        ),
      ).toEqual(refused('no-payload'));
    });
  });

  describe.each(['form', 'terminal'] as const)('a pasted text (%s)', (via) => {
    /** What an unreadable paste is on this channel. */
    const unreadable = (verdict: AnswerVerdict<unknown>) => {
      if (via === 'form') {
        expect(verdict).toEqual(refused('unreadable'));
        return;
      }
      expect(endError(verdict)).toMatchObject({
        kind: 'interactive-login',
        facts: { outcome: 'unreadable-input' },
      });
    };

    it.each([
      ['a bare code', CODE],
      ['a bare code with spaces around it', `  ${CODE}\n`],
      [
        'the whole redirected URL with the right state',
        `http://localhost:61001/callback?code=${CODE}&state=${STATE}`,
      ],
      ['a relative redirect', `/callback?state=${STATE}&code=${CODE}`],
    ])('%s → accept', (_c, pasted) => {
      expect(judge()(text(via, pasted))).toEqual({
        verdict: 'accept',
        payload: payloadOf(CODE, via),
      });
    });

    it.each([
      [
        'a URL with a wrong state',
        `http://localhost:61001/callback?code=${CODE}&state=${OTHER}`,
      ],
      ['a URL without state', `http://localhost:61001/callback?code=${CODE}`],
      [
        'a URL with two states',
        `http://localhost:61001/callback?code=${CODE}&state=${STATE}&state=${STATE}`,
      ],
      [
        '…/callback&code=X (not bare: no query, so no state)',
        `http://localhost:61001/callback&code=${CODE}`,
      ],
      ['code=X (not bare)', `code=${CODE}`],
      ['a code with a slash', `${CODE}/x`],
      [
        'the state in a fragment only',
        `http://localhost/callback?code=${CODE}#state=${STATE}`,
      ],
    ])('%s → refuse pasted-state', (_c, pasted) => {
      expect(judge()(text(via, pasted))).toEqual(refused('pasted-state'));
    });

    it.each([
      ['nothing', ''],
      ['blanks', '   '],
      ['two words', `${CODE} ${CODE}`],
      [
        'a URL with the right state and no code',
        `http://localhost/callback?state=${STATE}`,
      ],
      [
        'a URL with the right state and two codes',
        `http://localhost/callback?state=${STATE}&code=${CODE}&code=${CODE}`,
      ],
      [
        'a URL whose code is only in the fragment',
        `http://localhost/callback?state=${STATE}#code=${CODE}`,
      ],
    ])('%s → unreadable', (_c, pasted) => {
      unreadable(judge()(text(via, pasted)));
    });
  });

  describe('a consumer text', () => {
    it('is the code, verbatim', () => {
      expect(judge()(text('consumer', ` ${CODE} `))).toEqual({
        verdict: 'accept',
        payload: payloadOf(` ${CODE} `, 'consumer'),
      });
    });

    it('empty → end no-input', () => {
      expect(endError(judge()(text('consumer', '')))).toMatchObject({
        kind: 'interactive-login',
        facts: { outcome: 'no-input' },
      });
    });
  });
});

/** The two text protocols. */
describe.each([
  ['samlResponse', samlResponse, 'PHNhbWw+', 'SAMLResponse'],
  ['passcode', passcode, 'PASSCODE-77', 'code'],
] as const)('%s', (name, make, value, parameter) => {
  const judge = (): AnswerJudge<string> => make().begin('not even a URL');

  it('declares its redirect, its methods and its paste words', () => {
    const protocol = make();
    if (name === 'samlResponse') {
      expect(protocol.redirect).toBe('required');
      expect(protocol.callbackMethods).toEqual(['GET', 'POST']);
    } else {
      expect(protocol.redirect).toBe('unused');
      expect(protocol.callbackMethods).toEqual([]);
    }
    expect(protocol.paste?.prompt).toEqual(expect.any(String));
    expect(protocol.paste?.instructions).toEqual(expect.any(String));
  });

  it.each(['GET', 'POST'] as const)('a redirect by %s', (method) => {
    const verdict = judge()(
      redirect(
        `${parameter}=${encodeURIComponent(value)}&state=${OTHER}`,
        method,
      ),
    );
    expect(verdict).toEqual(
      name === 'samlResponse'
        ? { verdict: 'accept', payload: value }
        : refused('no-payload'),
    );
  });

  it.each([
    ['none', 'RelayState=x'],
    ['an empty one', `${parameter}=`],
    ['two', `${parameter}=${value}&${parameter}=${value}`],
  ])('a redirect with %s → refuse no-payload', (_c, query) => {
    expect(judge()(redirect(query, 'POST'))).toEqual(refused('no-payload'));
  });

  it.each(['form', 'terminal', 'consumer'] as const)(
    'a %s text, trimmed → accept',
    (via) => {
      expect(judge()(text(via, `  ${value}\n`))).toEqual({
        verdict: 'accept',
        payload: value,
      });
    },
  );

  it('an empty form text → refuse no-payload', () => {
    expect(judge()(text('form', '  '))).toEqual(refused('no-payload'));
  });

  it.each(['terminal', 'consumer'] as const)(
    'an empty %s text → end no-input',
    (via) => {
      expect(endError(judge()(text(via, ' \n')))).toMatchObject({
        kind: 'interactive-login',
        facts: { outcome: 'no-input' },
      });
    },
  );
});
