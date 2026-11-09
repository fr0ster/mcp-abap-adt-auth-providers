/**
 * The transports without a socket:
 * `terminalPaste` (an injected `read`), `consumerAnswer` and the
 * `consumerHandoff` pair — what each advertises, what each does per
 * verdict, and how each ends at an abort. Driven with the shipped
 * protocols' judges.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type {
  AnswerJudge,
  AnswerTransportOptions,
  IAnswerChannel,
  IAnswerTransport,
  IAuthorizationProtocol,
} from '@mcp-abap-adt/interfaces-auth';
import { ANSWER_WORDS } from '../../authorization/answerWords';
import {
  oauthCode,
  oidcCode,
  passcode,
  samlResponse,
} from '../../authorization/protocol';
import {
  consumerAnswer,
  consumerHandoff,
  terminalPaste,
} from '../../authorization/transport';
import {
  cases,
  caseTitle,
  matchObject,
  notContains,
} from '../helpers/expectations';

const STATE = 'Xy9-state-of-this-login_0123456789abcdef';
const REDIRECT = 'http://localhost:61001/callback';
const URL_SHOWN = `https://idp.example/oauth/authorize?client_id=c&state=${STATE}`;

type Protocol = IAuthorizationProtocol<unknown>;

const failureOf = (thrown: unknown) => readFailure(thrown, 'browser-login');

function optionsFor(
  protocol: Protocol,
  signal: AbortSignal = new AbortController().signal,
): AnswerTransportOptions {
  return {
    signal,
    paste: protocol.paste,
    callbackMethods: protocol.callbackMethods,
    endpoint: '/callback',
  };
}

/** Opens, arms with the protocol's judge, awaits the answer: the payload. */
async function answered(
  transport: IAnswerTransport,
  protocol: Protocol,
  signal?: AbortSignal,
  seen?: (channel: IAnswerChannel) => void,
): Promise<unknown> {
  return transport.open(optionsFor(protocol, signal), async (channel) => {
    seen?.(channel);
    let payload: unknown;
    const judge = protocol.begin(URL_SHOWN);
    await channel
      .arm((answer) => {
        const verdict = judge(answer);
        if (verdict.verdict === 'accept') payload = verdict.payload;
        return verdict;
      })
      .answer();
    return payload;
  });
}

const configurationOf = (run: () => unknown) => {
  try {
    run();
  } catch (error) {
    return failureOf(error);
  }
  return undefined;
};

/** A reader answering the given lines in turn, recording each prompt. */
function scripted(lines: readonly string[]) {
  const prompts: string[] = [];
  let next = 0;
  const read = async (prompt: string, _signal: AbortSignal) => {
    prompts.push(prompt);
    const line = lines[next];
    next += 1;
    if (line === undefined) throw new Error('read past the script');
    return line;
  };
  return { read, prompts };
}

describe('terminalPaste', () => {
  it('advertises the consumer’s redirect, or none; label manual', async () => {
    const given = terminalPaste({
      redirectUri: REDIRECT,
      read: scripted(['c']).read,
    });
    const none = terminalPaste({ read: scripted(['c']).read });
    assert.equal(given.label, 'manual');
    let channels: (string | undefined)[] = [];
    await answered(given, oauthCode() as Protocol, undefined, (c) => {
      channels = [...channels, c.redirectUri];
    });
    await answered(none, passcode(), undefined, (c) => {
      channels = [...channels, c.redirectUri];
    });
    assert.deepEqual(channels, [REDIRECT, undefined]);
  });

  for (const [caseIndex, caseRow] of cases([
    ['not a URL', 'localhost:61001/callback'],
    ['not http(s)', 'ftp://localhost/callback'],
    ['relative', '/callback'],
  ]).entries()) {
    const [_why, redirectUri] = caseRow;
    it(
      caseTitle(
        'a redirectUri %s is refused at construction',
        caseRow,
        caseIndex,
      ),
      () => {
        matchObject(
          configurationOf(() => terminalPaste({ redirectUri } as never)),
          {
            kind: 'configuration',
            facts: { case: 'invalid-value', fields: ['redirectUri'] },
          },
        );
      },
    );
  }

  it('reads nothing before it is armed', async () => {
    const { read, prompts } = scripted(['c']);
    await terminalPaste({ read }).open(optionsFor(passcode()), async () => {
      await new Promise((resolve) => setImmediate(resolve));
    });
    assert.deepEqual(prompts, []);
  });

  it('oauthCode: a pasted URL from another login → the reason’s words, then the prompt again; a bare code logs in', async () => {
    const { read, prompts } = scripted([
      'http://localhost/callback?code=c&state=another-login',
      'the-code',
    ]);
    const payload = await answered(terminalPaste({ read }), oauthCode());
    assert.equal(payload, 'the-code');
    const prompt = oauthCode().paste?.prompt as string;
    assert.deepEqual(prompts, [
      prompt,
      `${ANSWER_WORDS['pasted-state']} ${prompt}`,
    ]);
  });

  it('oidcCode: a pasted URL with this login’s state logs in', async () => {
    const { read } = scripted([
      `http://localhost/callback?code=the-code&state=${STATE}`,
    ]);
    assert.deepEqual(
      await answered(terminalPaste({ read }), oidcCode() as Protocol),
      {
        code: 'the-code',
        state: undefined,
      },
    );
  });

  it('oauthCode: an unreadable paste ends unreadable-input (a terminal is not asked twice)', async () => {
    const { read, prompts } = scripted([
      `http://localhost/callback?state=${STATE}`,
    ]);
    const thrown = await answered(terminalPaste({ read }), oauthCode()).catch(
      (error: unknown) => error,
    );
    assert.deepEqual(failureOf(thrown).facts, { outcome: 'unreadable-input' });
    assert.equal(prompts.length, 1);
  });

  for (const [caseIndex, caseRow] of (
    [
      ['samlResponse', samlResponse],
      ['passcode', passcode],
    ] as const
  ).entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: a text, trimmed, logs in; an empty one ends no-input',
        caseRow,
        caseIndex,
      ),
      async () => {
        assert.equal(
          await answered(
            terminalPaste({ read: scripted(['  text  ']).read }),
            make(),
          ),
          'text',
        );
        const thrown = await answered(
          terminalPaste({ read: scripted(['   ']).read }),
          make(),
        ).catch((error: unknown) => error);
        assert.deepEqual(failureOf(thrown).facts, { outcome: 'no-input' });
      },
    );
  }

  it('a protocol without paste words cannot be used with a terminal', async () => {
    const bare: Protocol = { ...oauthCode(), paste: undefined };
    let entered = false;
    const thrown = await terminalPaste({ read: scripted(['c']).read })
      .open(optionsFor(bare), async () => {
        entered = true;
      })
      .catch((error: unknown) => error);
    assert.equal(entered, false);
    matchObject(failureOf(thrown), {
      kind: 'configuration',
      facts: { case: 'invalid-value', fields: ['protocol'] },
    });
  });

  it('a read’s own failure passes as it is (no terminal)', async () => {
    const { loginFailure } = await import('../../auth/interactiveLogin');
    const read = async () => {
      throw loginFailure({ outcome: 'no-terminal' });
    };
    const thrown = await answered(terminalPaste({ read }), passcode()).catch(
      (error: unknown) => error,
    );
    assert.deepEqual(failureOf(thrown).facts, { outcome: 'no-terminal' });
  });

  it('an abort ends it aborted (manual) — and only once the read in flight has settled', async () => {
    const controller = new AbortController();
    const order: string[] = [];
    const read = (_prompt: string, signal: AbortSignal) =>
      new Promise<string>((_resolve, reject) => {
        signal.addEventListener('abort', () => {
          // The reader releases what it holds a few turns later.
          setImmediate(() =>
            setImmediate(() => {
              order.push('reader closed');
              reject(new Error('closed'));
            }),
          );
        });
        setImmediate(() => controller.abort());
      });
    const thrown = await answered(
      terminalPaste({ read }),
      passcode(),
      controller.signal,
    ).catch((error: unknown) => {
      order.push('open settled');
      return error;
    });
    assert.deepEqual(failureOf(thrown).facts, {
      outcome: 'aborted',
      strategy: 'manual',
    });
    assert.deepEqual(order, ['reader closed', 'open settled']);
  });

  it('an already-aborted signal reads nothing and enters nothing', async () => {
    const controller = new AbortController();
    controller.abort();
    const { read, prompts } = scripted(['c']);
    let entered = false;
    const thrown = await terminalPaste({ read })
      .open(optionsFor(passcode(), controller.signal), async () => {
        entered = true;
      })
      .catch((error: unknown) => error);
    assert.deepEqual(failureOf(thrown).facts, {
      outcome: 'aborted',
      strategy: 'manual',
    });
    assert.equal(entered, false);
    assert.deepEqual(prompts, []);
  });

  it('use ending while a read is in flight stops the read before open settles', async () => {
    const order: string[] = [];
    const read = (_prompt: string, signal: AbortSignal) =>
      new Promise<string>((_resolve, reject) => {
        signal.addEventListener('abort', () =>
          setImmediate(() => {
            order.push('reader closed');
            reject(new Error('closed'));
          }),
        );
      });
    const result = await terminalPaste({ read }).open(
      optionsFor(passcode()),
      async (channel) => {
        void channel
          .arm(passcode().begin('') as AnswerJudge<unknown>)
          .answer()
          .catch(() => undefined);
        await new Promise((resolve) => setImmediate(resolve));
        return 'done';
      },
    );
    order.push('open settled');
    assert.equal(result, 'done');
    assert.deepEqual(order, ['reader closed', 'open settled']);
  });
});

describe('consumerAnswer', () => {
  it('advertises the consumer’s redirect or none; label consumer', async () => {
    const transport = consumerAnswer({
      redirectUri: REDIRECT,
      receive: async () => 'the-code',
    });
    assert.equal(transport.label, 'consumer');
    let redirect: string | undefined;
    assert.equal(
      await answered(transport, oauthCode(), undefined, (c) => {
        redirect = c.redirectUri;
      }),
      'the-code',
    );
    assert.equal(redirect, REDIRECT);
  });

  it('receive gets the composition’s signal', async () => {
    const controller = new AbortController();
    let given: AbortSignal | undefined;
    await answered(
      consumerAnswer({
        receive: async (signal) => {
          given = signal;
          return 'c';
        },
      }),
      oauthCode(),
      controller.signal,
    );
    assert.equal(given?.aborted, false);
    controller.abort();
    assert.equal(given?.aborted, true);
  });

  it('a refusal ends unreadable-input (it cannot ask again); an end ends with its error', async () => {
    const refusing: Protocol = {
      ...oauthCode(),
      begin: () => () => ({ verdict: 'refuse', reason: 'no-payload' }),
    };
    const refused = await answered(
      consumerAnswer({ receive: async () => 'x' }),
      refusing,
    ).catch((error: unknown) => error);
    assert.deepEqual(failureOf(refused).facts, { outcome: 'unreadable-input' });
    const empty = await answered(
      consumerAnswer({ receive: async () => '' }),
      oauthCode(),
    ).catch((error: unknown) => error);
    assert.deepEqual(failureOf(empty).facts, { outcome: 'no-input' });
  });

  it('a receive that rejects passes its rejection on', async () => {
    const own = new Error('the consumer’s own');
    const rejected = await answered(
      consumerAnswer({
        receive: async () => {
          throw own;
        },
      }),
      oauthCode(),
    ).catch((error: unknown) => error);
    assert.equal(rejected, own);
  });

  it('an abort settles at the abort itself (consumer), a receive that never settles notwithstanding', async () => {
    const controller = new AbortController();
    const thrown = await answered(
      consumerAnswer({
        receive: () => {
          setImmediate(() => controller.abort());
          return new Promise<string>(() => undefined);
        },
      }),
      oauthCode(),
      controller.signal,
    ).catch((error: unknown) => error);
    assert.deepEqual(failureOf(thrown).facts, {
      outcome: 'aborted',
      strategy: 'consumer',
    });
  });
});

describe('consumerHandoff', () => {
  it('the presentation calls provide with the URL and signal; the transport awaits what it returned', async () => {
    const controller = new AbortController();
    const calls: [string, AbortSignal][] = [];
    const { presentation, transport } = consumerHandoff({
      redirectUri: REDIRECT,
      provide: async (url, signal) => {
        calls.push([url, signal]);
        return 'the-code';
      },
    });
    assert.equal(transport.label, 'consumer');
    const protocol = oauthCode();
    const payload = await transport.open(
      optionsFor(protocol, controller.signal),
      async (channel) => {
        assert.equal(channel.redirectUri, REDIRECT);
        let kept: unknown;
        const judge = protocol.begin(URL_SHOWN);
        const armed = channel.arm((answer) => {
          const verdict = judge(answer);
          if (verdict.verdict === 'accept') kept = verdict.payload;
          return verdict;
        });
        presentation.present(URL_SHOWN, {
          redirectUri: channel.redirectUri,
          signal: controller.signal,
        });
        await armed.answer();
        return kept;
      },
    );
    assert.equal(payload, 'the-code');
    assert.equal(calls.length, 1);
    assert.equal(calls[0]?.[0], URL_SHOWN);
    assert.equal(calls[0]?.[1], controller.signal);
  });

  it('provide failing ends the wait with its failure; the presentation itself does not fail', async () => {
    const own = new Error('the consumer’s own');
    const { presentation, transport } = consumerHandoff({
      provide: () => {
        throw own;
      },
    });
    const controller = new AbortController();
    const thrown = await transport
      .open(optionsFor(oauthCode(), controller.signal), async (channel) => {
        const armed = channel.arm(
          oauthCode().begin(URL_SHOWN) as AnswerJudge<unknown>,
        );
        assert.doesNotThrow(() =>
          presentation.present(URL_SHOWN, {
            redirectUri: undefined,
            signal: controller.signal,
          }),
        );
        await armed.answer();
      })
      .catch((error: unknown) => error);
    assert.equal(thrown, own);
  });

  it('an abort settles at the abort itself (consumer)', async () => {
    const controller = new AbortController();
    const { presentation, transport } = consumerHandoff({
      provide: () => new Promise<string>(() => undefined),
    });
    const thrown = await transport
      .open(optionsFor(oauthCode(), controller.signal), async (channel) => {
        const armed = channel.arm(
          oauthCode().begin(URL_SHOWN) as AnswerJudge<unknown>,
        );
        presentation.present(URL_SHOWN, {
          redirectUri: undefined,
          signal: controller.signal,
        });
        setImmediate(() => controller.abort());
        await armed.answer();
      })
      .catch((error: unknown) => error);
    assert.deepEqual(failureOf(thrown).facts, {
      outcome: 'aborted',
      strategy: 'consumer',
    });
  });
});

describe('a judge that throws (review m3)', () => {
  const throwing: AnswerJudge<unknown> = () => {
    throw new Error('judge secret text');
  };
  const run = (transport: IAnswerTransport) =>
    transport
      .open(optionsFor(passcode()), async (channel) => {
        await channel.arm(throwing).answer();
      })
      .catch((error: unknown) => error);

  for (const [caseIndex, caseRow] of (
    [
      ['terminalPaste', () => terminalPaste({ read: scripted(['x']).read })],
      ['consumerAnswer', () => consumerAnswer({ receive: async () => 'x' })],
    ] as const
  ).entries()) {
    const [_name, make] = caseRow;
    it(
      caseTitle(
        '%s: failed, nothing of the throw anywhere',
        caseRow,
        caseIndex,
      ),
      async () => {
        const thrown = await run(make());
        assert.deepEqual(failureOf(thrown).facts, { outcome: 'failed' });
        notContains(String(thrown), 'judge secret text');
        notContains(JSON.stringify(thrown), 'judge secret text');
        assert.equal((thrown as { cause?: unknown }).cause, undefined);
      },
    );
  }
});
