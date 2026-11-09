/**
 * The shipped protocols' judges, per protocol and per `via`;
 * a parameter counts only when present exactly once; a bare
 * paste only without `? & = / #`, a pasted URL must carry the expected
 * `state`. Also the protocol's rows of Form, and Logs: no code,
 * `state`, pasted text or `SAMLResponse` in a verdict's error or a thrown
 * one.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
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
import {
  cases,
  caseTitle,
  matchObject,
  notContains,
} from '../helpers/expectations';
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
  assert.equal(verdict.verdict, 'end');
  if (verdict.verdict !== 'end') throw new Error('not an end');
  const rendered = JSON.stringify(verdict.error) + String(verdict.error.reason);
  for (const secret of SECRETS) notContains(rendered, secret);
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

for (const [caseIndex, caseRow] of CODE_PROTOCOLS.entries()) {
  const [_name, make, payloadOf] = caseRow;
  describe(caseTitle('%s', caseRow, caseIndex), () => {
    const judge = (): AnswerJudge<unknown> => make().begin(URL_WITH_STATE);

    it('takes a redirect by GET and has paste words', () => {
      const protocol = make();
      assert.equal(protocol.redirect, 'required');
      assert.deepEqual(protocol.callbackMethods, ['GET']);
      assert.equal(typeof protocol.paste?.prompt, 'string');
      assert.equal(typeof protocol.paste?.instructions, 'string');
    });

    describe('begin: the URL must carry exactly one state', () => {
      for (const [caseIndex, caseRow] of cases([
        ['a URL that does not parse', 'not a url'],
        ['a URL without state', 'https://uaa.example/oauth/authorize?a=1'],
        [
          'a URL with two states',
          `https://uaa.example/authorize?state=${STATE}&state=${STATE}`,
        ],
        ['a URL with an empty state', 'https://uaa.example/authorize?state='],
      ]).entries()) {
        const [_c, url] = caseRow;
        it(
          caseTitle(
            '%s → configuration invalid-value authorizationUrl',
            caseRow,
            caseIndex,
          ),
          async () => {
            const thrown = await thrownFrom(() => make().begin(url));
            matchObject(configurationOf(thrown), {
              case: 'invalid-value',
              fields: ['authorizationUrl'],
            });
            const rendered = JSON.stringify(
              readFailure(thrown, 'unfamiliar-error'),
            );
            notContains(rendered, STATE);
            notContains(rendered, 'uaa.example');
          },
        );
      }
    });

    describe('redirect: the binding first', () => {
      for (const [caseIndex, caseRow] of cases([
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
      ]).entries()) {
        const [_c, query] = caseRow;
        it(caseTitle('%s → refuse state', caseRow, caseIndex), () => {
          assert.deepEqual(judge()(redirect(query)), refused('state'));
        });
      }

      it('none, two, a wrong and then the right state: refused thrice, then accepted', () => {
        const once = judge();
        assert.deepEqual(once(redirect(`code=${CODE}`)), refused('state'));
        assert.deepEqual(
          once(redirect(`state=${STATE}&state=${OTHER}&code=${CODE}`)),
          refused('state'),
        );
        assert.deepEqual(
          once(redirect(`state=${OTHER}&code=${CODE}`)),
          refused('state'),
        );
        assert.deepEqual(once(redirect(`state=${STATE}&code=${CODE}`)), {
          verdict: 'accept',
          payload: payloadOf(CODE, 'redirect'),
        });
      });

      for (const [caseIndex, caseRow] of (['GET', 'POST'] as const).entries()) {
        const method = caseRow;
        it(
          caseTitle(
            'the right state and one code by %s → accept',
            caseRow,
            caseIndex,
          ),
          () => {
            assert.deepEqual(
              judge()(redirect(`state=${STATE}&code=${CODE}`, method)),
              {
                verdict: 'accept',
                payload: payloadOf(CODE, 'redirect'),
              },
            );
          },
        );
      }

      for (const [caseIndex, caseRow] of cases([
        ['no code', `state=${STATE}`],
        ['two codes', `state=${STATE}&code=${CODE}&code=${CODE}`],
        ['an empty code', `state=${STATE}&code=`],
      ]).entries()) {
        const [_c, query] = caseRow;
        it(
          caseTitle(
            'the right state and %s → refuse no-payload',
            caseRow,
            caseIndex,
          ),
          () => {
            assert.deepEqual(judge()(redirect(query)), refused('no-payload'));
          },
        );
      }

      it('the right state and a registered error → end identity-provider-refused, shown for the page only', () => {
        const verdict = judge()(
          redirect(
            `state=${STATE}&error=access_denied&error_description=desc-text&code=${CODE}`,
          ),
        );
        const error = endError(verdict);
        matchObject(error, {
          kind: 'interactive-login',
          facts: {
            outcome: 'identity-provider-refused',
            oauthError: 'access_denied',
          },
        });
        matchObject(verdict, { shown: 'access_denied: desc-text' });
      });

      it('an unregistered error is kept out of the facts, and shown alone without a description', () => {
        const verdict = judge()(redirect(`state=${STATE}&error=made_up_code`));
        const error = endError(verdict);
        assert.equal(error.kind, 'interactive-login');
        assert.deepEqual(error.facts, { outcome: 'identity-provider-refused' });
        matchObject(verdict, { shown: 'made_up_code' });
        notContains(JSON.stringify(error), 'made_up_code');
      });

      it('two errors are no error: the code decides', () => {
        assert.deepEqual(
          judge()(
            redirect(`state=${STATE}&error=access_denied&error=access_denied`),
          ),
          refused('no-payload'),
        );
      });
    });

    for (const [caseIndex, caseRow] of (
      ['form', 'terminal'] as const
    ).entries()) {
      const via = caseRow;
      describe(caseTitle('a pasted text (%s)', caseRow, caseIndex), () => {
        /** What an unreadable paste is on this channel. */
        const unreadable = (verdict: AnswerVerdict<unknown>) => {
          if (via === 'form') {
            assert.deepEqual(verdict, refused('unreadable'));
            return;
          }
          matchObject(endError(verdict), {
            kind: 'interactive-login',
            facts: { outcome: 'unreadable-input' },
          });
        };

        for (const [caseIndex, caseRow] of cases([
          ['a bare code', CODE],
          ['a bare code with spaces around it', `  ${CODE}\n`],
          [
            'the whole redirected URL with the right state',
            `http://localhost:61001/callback?code=${CODE}&state=${STATE}`,
          ],
          ['a relative redirect', `/callback?state=${STATE}&code=${CODE}`],
        ]).entries()) {
          const [_c, pasted] = caseRow;
          it(caseTitle('%s → accept', caseRow, caseIndex), () => {
            assert.deepEqual(judge()(text(via, pasted)), {
              verdict: 'accept',
              payload: payloadOf(CODE, via),
            });
          });
        }

        for (const [caseIndex, caseRow] of cases([
          [
            'a URL with a wrong state',
            `http://localhost:61001/callback?code=${CODE}&state=${OTHER}`,
          ],
          [
            'a URL without state',
            `http://localhost:61001/callback?code=${CODE}`,
          ],
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
        ]).entries()) {
          const [_c, pasted] = caseRow;
          it(caseTitle('%s → refuse pasted-state', caseRow, caseIndex), () => {
            assert.deepEqual(
              judge()(text(via, pasted)),
              refused('pasted-state'),
            );
          });
        }

        for (const [caseIndex, caseRow] of cases([
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
        ]).entries()) {
          const [_c, pasted] = caseRow;
          it(caseTitle('%s → unreadable', caseRow, caseIndex), () => {
            unreadable(judge()(text(via, pasted)));
          });
        }
      });
    }

    describe('a consumer text', () => {
      it('is the code, verbatim', () => {
        assert.deepEqual(judge()(text('consumer', ` ${CODE} `)), {
          verdict: 'accept',
          payload: payloadOf(` ${CODE} `, 'consumer'),
        });
      });

      it('empty → end no-input', () => {
        matchObject(endError(judge()(text('consumer', ''))), {
          kind: 'interactive-login',
          facts: { outcome: 'no-input' },
        });
      });
    });
  });
}

/** The two text protocols. */
for (const [caseIndex, caseRow] of (
  [
    ['samlResponse', samlResponse, 'PHNhbWw+', 'SAMLResponse'],
    ['passcode', passcode, 'PASSCODE-77', 'code'],
  ] as const
).entries()) {
  const [name, make, value, parameter] = caseRow;
  describe(caseTitle('%s', caseRow, caseIndex), () => {
    const judge = (): AnswerJudge<string> => make().begin('not even a URL');

    it('declares its redirect, its methods and its paste words', () => {
      const protocol = make();
      if (name === 'samlResponse') {
        assert.equal(protocol.redirect, 'required');
        assert.deepEqual(protocol.callbackMethods, ['GET', 'POST']);
      } else {
        assert.equal(protocol.redirect, 'unused');
        assert.deepEqual(protocol.callbackMethods, []);
      }
      assert.equal(typeof protocol.paste?.prompt, 'string');
      assert.equal(typeof protocol.paste?.instructions, 'string');
    });

    for (const [caseIndex, caseRow] of (['GET', 'POST'] as const).entries()) {
      const method = caseRow;
      it(caseTitle('a redirect by %s', caseRow, caseIndex), () => {
        const verdict = judge()(
          redirect(
            `${parameter}=${encodeURIComponent(value)}&state=${OTHER}`,
            method,
          ),
        );
        assert.deepEqual(
          verdict,
          name === 'samlResponse'
            ? { verdict: 'accept', payload: value }
            : refused('no-payload'),
        );
      });
    }

    for (const [caseIndex, caseRow] of cases([
      ['none', 'RelayState=x'],
      ['an empty one', `${parameter}=`],
      ['two', `${parameter}=${value}&${parameter}=${value}`],
    ]).entries()) {
      const [_c, query] = caseRow;
      it(
        caseTitle('a redirect with %s → refuse no-payload', caseRow, caseIndex),
        () => {
          assert.deepEqual(
            judge()(redirect(query, 'POST')),
            refused('no-payload'),
          );
        },
      );
    }

    for (const [caseIndex, caseRow] of (
      ['form', 'terminal', 'consumer'] as const
    ).entries()) {
      const via = caseRow;
      it(caseTitle('a %s text, trimmed → accept', caseRow, caseIndex), () => {
        assert.deepEqual(judge()(text(via, `  ${value}\n`)), {
          verdict: 'accept',
          payload: value,
        });
      });
    }

    it('an empty form text → refuse no-payload', () => {
      assert.deepEqual(judge()(text('form', '  ')), refused('no-payload'));
    });

    for (const [caseIndex, caseRow] of (
      ['terminal', 'consumer'] as const
    ).entries()) {
      const via = caseRow;
      it(
        caseTitle('an empty %s text → end no-input', caseRow, caseIndex),
        () => {
          matchObject(endError(judge()(text(via, ' \n'))), {
            kind: 'interactive-login',
            facts: { outcome: 'no-input' },
          });
        },
      );
    }
  });
}
