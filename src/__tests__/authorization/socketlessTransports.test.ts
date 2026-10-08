/**
 * The transports without a socket (spec §6d.2, §6d.3.2, C4):
 * `terminalPaste` (an injected `read`), `consumerAnswer` and the
 * `consumerHandoff` pair — what each advertises, what each does per
 * verdict, and how each ends at an abort. Driven with the shipped
 * protocols' judges.
 */

import { describe, expect, it } from '@jest/globals';
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

describe('terminalPaste (spec §6d.2)', () => {
  it('advertises the consumer’s redirect, or none (C4); label manual', async () => {
    const given = terminalPaste({
      redirectUri: REDIRECT,
      read: scripted(['c']).read,
    });
    const none = terminalPaste({ read: scripted(['c']).read });
    expect(given.label).toBe('manual');
    let channels: (string | undefined)[] = [];
    await answered(given, oauthCode() as Protocol, undefined, (c) => {
      channels = [...channels, c.redirectUri];
    });
    await answered(none, passcode(), undefined, (c) => {
      channels = [...channels, c.redirectUri];
    });
    expect(channels).toEqual([REDIRECT, undefined]);
  });

  it.each([
    ['not a URL', 'localhost:61001/callback'],
    ['not http(s)', 'ftp://localhost/callback'],
    ['relative', '/callback'],
    ['not a string', 42],
  ])('a redirectUri %s is refused at construction', (_why, redirectUri) => {
    expect(
      configurationOf(() => terminalPaste({ redirectUri } as never)),
    ).toMatchObject({
      kind: 'configuration',
      facts: { case: 'invalid-value', fields: ['redirectUri'] },
    });
  });

  it('a read that is not a function is refused at construction', () => {
    expect(
      configurationOf(() => terminalPaste({ read: 'stdin' } as never)),
    ).toMatchObject({
      kind: 'configuration',
      facts: { case: 'invalid-value', fields: ['read'] },
    });
  });

  it('reads nothing before it is armed', async () => {
    const { read, prompts } = scripted(['c']);
    await terminalPaste({ read }).open(optionsFor(passcode()), async () => {
      await new Promise((resolve) => setImmediate(resolve));
    });
    expect(prompts).toEqual([]);
  });

  it('oauthCode: a pasted URL from another login → the reason’s words, then the prompt again; a bare code logs in', async () => {
    const { read, prompts } = scripted([
      'http://localhost/callback?code=c&state=another-login',
      'the-code',
    ]);
    const payload = await answered(terminalPaste({ read }), oauthCode());
    expect(payload).toBe('the-code');
    const prompt = oauthCode().paste?.prompt as string;
    expect(prompts).toEqual([
      prompt,
      `${ANSWER_WORDS['pasted-state']} ${prompt}`,
    ]);
  });

  it('oidcCode: a pasted URL with this login’s state logs in', async () => {
    const { read } = scripted([
      `http://localhost/callback?code=the-code&state=${STATE}`,
    ]);
    expect(
      await answered(terminalPaste({ read }), oidcCode() as Protocol),
    ).toEqual({
      code: 'the-code',
      state: undefined,
    });
  });

  it('oauthCode: an unreadable paste ends unreadable-input (a terminal is not asked twice)', async () => {
    const { read, prompts } = scripted([
      `http://localhost/callback?state=${STATE}`,
    ]);
    const thrown = await answered(terminalPaste({ read }), oauthCode()).catch(
      (error: unknown) => error,
    );
    expect(failureOf(thrown).facts).toEqual({ outcome: 'unreadable-input' });
    expect(prompts).toHaveLength(1);
  });

  it.each([
    ['samlResponse', samlResponse],
    ['passcode', passcode],
  ] as const)(
    '%s: a text, trimmed, logs in; an empty one ends no-input',
    async (_name, make) => {
      expect(
        await answered(
          terminalPaste({ read: scripted(['  text  ']).read }),
          make(),
        ),
      ).toBe('text');
      const thrown = await answered(
        terminalPaste({ read: scripted(['   ']).read }),
        make(),
      ).catch((error: unknown) => error);
      expect(failureOf(thrown).facts).toEqual({ outcome: 'no-input' });
    },
  );

  it('a protocol without paste words cannot be used with a terminal', async () => {
    const bare: Protocol = { ...oauthCode(), paste: undefined };
    let entered = false;
    const thrown = await terminalPaste({ read: scripted(['c']).read })
      .open(optionsFor(bare), async () => {
        entered = true;
      })
      .catch((error: unknown) => error);
    expect(entered).toBe(false);
    expect(failureOf(thrown)).toMatchObject({
      kind: 'configuration',
      facts: { case: 'invalid-value', fields: ['protocol'] },
    });
  });

  it('a read answering no string ends no-input', async () => {
    const read = async () => undefined as unknown as string;
    const thrown = await answered(terminalPaste({ read }), passcode()).catch(
      (error: unknown) => error,
    );
    expect(failureOf(thrown).facts).toEqual({ outcome: 'no-input' });
  });

  it('a read’s own failure passes as it is (no terminal)', async () => {
    const { loginFailure } = await import('../../auth/interactiveLogin');
    const read = async () => {
      throw loginFailure({ outcome: 'no-terminal' });
    };
    const thrown = await answered(terminalPaste({ read }), passcode()).catch(
      (error: unknown) => error,
    );
    expect(failureOf(thrown).facts).toEqual({ outcome: 'no-terminal' });
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
    expect(failureOf(thrown).facts).toEqual({
      outcome: 'aborted',
      strategy: 'manual',
    });
    expect(order).toEqual(['reader closed', 'open settled']);
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
    expect(failureOf(thrown).facts).toEqual({
      outcome: 'aborted',
      strategy: 'manual',
    });
    expect(entered).toBe(false);
    expect(prompts).toEqual([]);
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
    expect(result).toBe('done');
    expect(order).toEqual(['reader closed', 'open settled']);
  });
});

describe('consumerAnswer (spec §6d.2)', () => {
  it('requires receive; advertises the consumer’s redirect or none; label consumer', async () => {
    expect(configurationOf(() => consumerAnswer({} as never))).toMatchObject({
      kind: 'configuration',
      facts: { case: 'required-fields-missing', fields: ['receive'] },
    });
    const transport = consumerAnswer({
      redirectUri: REDIRECT,
      receive: async () => 'the-code',
    });
    expect(transport.label).toBe('consumer');
    let redirect: string | undefined;
    expect(
      await answered(transport, oauthCode(), undefined, (c) => {
        redirect = c.redirectUri;
      }),
    ).toBe('the-code');
    expect(redirect).toBe(REDIRECT);
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
    expect(given?.aborted).toBe(false);
    controller.abort();
    expect(given?.aborted).toBe(true);
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
    expect(failureOf(refused).facts).toEqual({ outcome: 'unreadable-input' });
    const empty = await answered(
      consumerAnswer({ receive: async () => '' }),
      oauthCode(),
    ).catch((error: unknown) => error);
    expect(failureOf(empty).facts).toEqual({ outcome: 'no-input' });
  });

  it('a receive answering no string ends no-input; one that rejects passes its rejection on', async () => {
    const none = await answered(
      consumerAnswer({ receive: async () => undefined as unknown as string }),
      oauthCode(),
    ).catch((error: unknown) => error);
    expect(failureOf(none).facts).toEqual({ outcome: 'no-input' });
    const own = new Error('the consumer’s own');
    const rejected = await answered(
      consumerAnswer({
        receive: async () => {
          throw own;
        },
      }),
      oauthCode(),
    ).catch((error: unknown) => error);
    expect(rejected).toBe(own);
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
    expect(failureOf(thrown).facts).toEqual({
      outcome: 'aborted',
      strategy: 'consumer',
    });
  });
});

describe('consumerHandoff (spec §6d.2)', () => {
  it('requires provide', () => {
    expect(configurationOf(() => consumerHandoff({} as never))).toMatchObject({
      kind: 'configuration',
      facts: { case: 'required-fields-missing', fields: ['provide'] },
    });
  });

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
    expect(transport.label).toBe('consumer');
    const protocol = oauthCode();
    const payload = await transport.open(
      optionsFor(protocol, controller.signal),
      async (channel) => {
        expect(channel.redirectUri).toBe(REDIRECT);
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
    expect(payload).toBe('the-code');
    expect(calls).toHaveLength(1);
    expect(calls[0]?.[0]).toBe(URL_SHOWN);
    expect(calls[0]?.[1]).toBe(controller.signal);
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
        expect(() =>
          presentation.present(URL_SHOWN, {
            redirectUri: undefined,
            signal: controller.signal,
          }),
        ).not.toThrow();
        await armed.answer();
      })
      .catch((error: unknown) => error);
    expect(thrown).toBe(own);
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
    expect(failureOf(thrown).facts).toEqual({
      outcome: 'aborted',
      strategy: 'consumer',
    });
  });
});
