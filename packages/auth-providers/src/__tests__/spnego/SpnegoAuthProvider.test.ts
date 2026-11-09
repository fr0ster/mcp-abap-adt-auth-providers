import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type {
  INegotiateTokenSource,
  IRequestTarget,
  NegotiateTokenOptions,
} from '@mcp-abap-adt/interfaces-auth';
import { NEGOTIATE_SOURCE_PROBLEMS } from '@mcp-abap-adt/interfaces-auth';
import { SpnegoAuthProvider } from '../../spnego/SpnegoAuthProvider';
import {
  cases,
  caseTitle,
  matchObject,
  notContains,
} from '../helpers/expectations';
import { configurationOf, mintedRefusal } from '../helpers/minted';
import {
  b64,
  gssKerberos,
  NTLM_NEGOTIATE,
  negTokenInit,
  OID_KRB5,
  OID_NTLM,
} from './fixtures/derParts';

const SPN = 'HTTP@sap.example.com';
/** A distinct Kerberos token per `n`: the body's length differs. */
const kerberos = (n = 0) => b64(gssKerberos(OID_KRB5, 64 + n));
/** NTLM wrapped in SPNEGO (a built fixture). */
const NTLM_IN_SPNEGO = b64(
  negTokenInit({ mechs: [OID_NTLM], mechToken: NTLM_NEGOTIATE }),
);

interface Call {
  readonly servicePrincipal: string;
  readonly options: NegotiateTokenOptions;
}

/** A source answering from a script, one entry per call, recording each call. */
function scriptedSource(...script: Array<() => unknown>) {
  const calls: Call[] = [];
  const source = {
    token(servicePrincipal: string, options: NegotiateTokenOptions) {
      calls.push({ servicePrincipal, options });
      const next = script[calls.length - 1] ?? script[script.length - 1];
      return next?.();
    },
  } as INegotiateTokenSource;
  return { source, calls };
}

/** A source answering a fresh Kerberos token on every call. */
function freshSource() {
  let n = 0;
  return scriptedSource(async () => {
    n += 1;
    return { ok: true, token: kerberos(n) };
  });
}

function recordingRequest(options: { throws?: boolean } = {}) {
  const written: Array<[string, string]> = [];
  const target: IRequestTarget = {
    header(name, value) {
      if (options.throws) throw new Error('target exploded: SECRET-IN-TARGET');
      written.push([name, value]);
    },
    cookies() {
      throw new Error('no cookies expected');
    },
  };
  return { target, written };
}

const provider = (source: INegotiateTokenSource, signal?: AbortSignal) =>
  new SpnegoAuthProvider({
    servicePrincipal: SPN,
    tokenSource: source,
    signal,
  });

function thrownBy(make: () => unknown): unknown {
  try {
    make();
  } catch (error) {
    return error;
  }
  throw new Error('expected a throw');
}

describe('construction', () => {
  const { source } = freshSource();
  for (const [caseIndex, caseRow] of [
    'HTTP@sap.example.com',
    'HTTP@h',
    'host-2@a-b.c',
    'HTTP@A1.b2-c.D',
  ].entries()) {
    const servicePrincipal = caseRow;
    it(caseTitle('accepts %p', caseRow, caseIndex), () => {
      assert.doesNotThrow(
        () => new SpnegoAuthProvider({ servicePrincipal, tokenSource: source }),
      );
    });
  }
  for (const [caseIndex, caseRow] of [
    '',
    ' HTTP@h',
    'HTTP@h ',
    'HTTP@',
    '@h',
    'HTTP',
    'HTTP@h@x',
    'HTTP/h@REALM',
    'HTTP/h',
    'HTTP@hö',
    'HTTP@h..x',
    'HTTP@.h',
    'HTTP@h.',
    'HTTP@-h',
    'HTTP@h-',
    'HTTP@a.-b',
    '2HTTP@h',
    '-HTTP@h',
    'HT_TP@h',
    'HTTP@h_x',
    'HTTP@h\tx',
    'HTTP\t@h',
    'HTTP@h\n',
  ].entries()) {
    const servicePrincipal = caseRow;
    it(caseTitle('refuses %p as invalid-value', caseRow, caseIndex), () => {
      const c = configurationOf(
        thrownBy(
          () =>
            new SpnegoAuthProvider({ servicePrincipal, tokenSource: source }),
        ),
      );
      matchObject(c, {
        case: 'invalid-value',
        fields: ['servicePrincipal'],
      });
      if (servicePrincipal !== '') {
        notContains(c.reason, servicePrincipal);
      }
    });
  }
  it('kind is spnego', () => {
    assert.equal(provider(source).kind, 'spnego');
  });
});

describe('prepare()', () => {
  it('asks the source once, with the service principal and a signal option', async () => {
    const { source, calls } = freshSource();
    assert.deepEqual(await provider(source).prepare(), { ok: true });
    assert.equal(calls.length, 1);
    assert.equal(calls[0]?.servicePrincipal, SPN);
    assert.deepEqual(Object.keys(calls[0]?.options ?? {}), ['signal']);
  });
  it('a SPNEGO token with Kerberos first is Ok', async () => {
    const token = b64(
      negTokenInit({ mechs: [OID_KRB5, OID_NTLM], mechToken: gssKerberos() }),
    );
    const { source } = scriptedSource(async () => ({ ok: true, token }));
    assert.deepEqual(await provider(source).prepare(), { ok: true });
  });
  for (const [caseIndex, caseRow] of NEGOTIATE_SOURCE_PROBLEMS.entries()) {
    const problem = caseRow;
    it(
      caseTitle(
        'a source problem %p is spnego with that problem',
        caseRow,
        caseIndex,
      ),
      async () => {
        const { source } = scriptedSource(async () => ({ ok: false, problem }));
        const error = mintedRefusal(await provider(source).prepare());
        matchObject(error, {
          kind: 'spnego',
          variant: problem,
          facts: { problem, operation: 'obtaining-negotiate-token' },
        });
      },
    );
  }
  for (const [caseIndex, caseRow] of cases([
    ['raw NTLM', b64(NTLM_NEGOTIATE)],
    ['NTLM inside SPNEGO', NTLM_IN_SPNEGO],
  ]).entries()) {
    const [_label, token] = caseRow;
    it(caseTitle('%s is ntlm-token', caseRow, caseIndex), async () => {
      const { source } = scriptedSource(async () => ({ ok: true, token }));
      const error = mintedRefusal(await provider(source).prepare());
      assert.deepEqual(error.facts, {
        problem: 'ntlm-token',
        operation: 'obtaining-negotiate-token',
      });
    });
  }
  for (const [caseIndex, caseRow] of cases([
    ['garbage', 'not-base64!'],
    ['an empty token', ''],
    ['base64 of nothing known', b64(Buffer.from('hello world'))],
  ]).entries()) {
    const [_label, token] = caseRow;
    it(caseTitle('%s is token-unreadable', caseRow, caseIndex), async () => {
      const { source } = scriptedSource(async () => ({ ok: true, token }));
      const error = mintedRefusal(await provider(source).prepare());
      assert.deepEqual(error.facts, {
        problem: 'token-unreadable',
        operation: 'obtaining-negotiate-token',
      });
    });
  }
  for (const [caseIndex, caseRow] of cases([
    [
      'a throw',
      () => {
        throw new Error('SOURCE-SECRET');
      },
    ],
    ['a rejection', async () => Promise.reject(new Error('SOURCE-SECRET'))],
    [
      'a thenable whose then throws',
      () => ({
        // biome-ignore lint/suspicious/noThenProperty: a thenable is the answer under test
        then() {
          throw new Error('SOURCE-SECRET');
        },
      }),
    ],
    [
      'an answer with throwing getters',
      async () =>
        Object.defineProperty({}, 'ok', {
          get() {
            throw new Error('SOURCE-SECRET');
          },
        }),
    ],
  ]).entries()) {
    const [_label, answer] = caseRow;
    it(
      caseTitle('%s is unknown with the operation', caseRow, caseIndex),
      async () => {
        const { source } = scriptedSource(answer);
        const outcome = await provider(source).prepare();
        const error = mintedRefusal(outcome);
        matchObject(error, {
          kind: 'unknown',
          facts: { operation: 'obtaining-negotiate-token' },
        });
        notContains(JSON.stringify(error), 'SOURCE-SECRET');
      },
    );
  }
  it('a synchronous answer is read as it is', async () => {
    const { source } = scriptedSource(() => ({ ok: true, token: kerberos() }));
    assert.deepEqual(await provider(source).prepare(), { ok: true });
  });
  it('a foreign thenable is adopted: its then called once', async () => {
    let calls = 0;
    const { source } = scriptedSource(() => ({
      // biome-ignore lint/suspicious/noThenProperty: a thenable is the answer under test
      then(resolve: (v: unknown) => void) {
        calls += 1;
        resolve({ ok: true, token: kerberos() });
      },
    }));
    assert.deepEqual(await provider(source).prepare(), { ok: true });
    assert.equal(calls, 1);
  });
  it('a native promise with an own then is adopted through that then', async () => {
    let calls = 0;
    const { source } = scriptedSource(() => {
      const p = Promise.resolve({ ok: true, token: kerberos() });
      Object.defineProperty(p, 'then', {
        value(...args: unknown[]) {
          calls += 1;
          return Promise.prototype.then.apply(p, args as never);
        },
      });
      return p;
    });
    assert.deepEqual(await provider(source).prepare(), { ok: true });
    assert.equal(calls, 1);
  });
  it('calls token with the source as this', async () => {
    const source = {
      seen: undefined as unknown,
      async token(this: { seen: unknown }) {
        this.seen = this;
        return { ok: true as const, token: kerberos() };
      },
    };
    await provider(source).prepare();
    assert.equal(source.seen, source);
  });
});

describe('authorize()', () => {
  it('asks the source for a new token every time, never reusing one', async () => {
    const { source, calls } = freshSource();
    const p = provider(source);
    await p.prepare();
    const { target, written } = recordingRequest();
    for (let i = 0; i < 3; i += 1) {
      assert.deepEqual(await p.authorize(target), { ok: true });
    }
    assert.equal(calls.length, 4);
    assert.deepEqual(written, [
      ['Authorization', `Negotiate ${kerberos(2)}`],
      ['Authorization', `Negotiate ${kerberos(3)}`],
      ['Authorization', `Negotiate ${kerberos(4)}`],
    ]);
  });
  it('without prepare(), each authorize asks the source', async () => {
    const { source, calls } = freshSource();
    const p = provider(source);
    const { target, written } = recordingRequest();
    await p.authorize(target);
    await p.authorize(target);
    assert.equal(calls.length, 2);
    assert.deepEqual(
      written.map(([, v]) => v),
      [`Negotiate ${kerberos(1)}`, `Negotiate ${kerberos(2)}`],
    );
    assert.equal(
      calls.every((c) => c.servicePrincipal === SPN),
      true,
    );
  });
  for (const [caseIndex, caseRow] of cases([
    [
      'a source problem',
      async () => ({ ok: false, problem: 'no-credential' }),
      { kind: 'spnego', problem: 'no-credential' },
    ],
    [
      'NTLM inside SPNEGO',
      async () => ({ ok: true, token: NTLM_IN_SPNEGO }),
      { kind: 'spnego', problem: 'ntlm-token' },
    ],
    [
      'raw NTLM',
      async () => ({ ok: true, token: b64(NTLM_NEGOTIATE) }),
      { kind: 'spnego', problem: 'ntlm-token' },
    ],
    [
      'garbage',
      async () => ({ ok: true, token: '%%%' }),
      { kind: 'spnego', problem: 'token-unreadable' },
    ],
    [
      'a throw',
      () => {
        throw new Error('x');
      },
      { kind: 'unknown' },
    ],
  ]).entries()) {
    const [_l, answer, expected] = caseRow;
    it(
      caseTitle(
        '%s: a refusal naming presenting-negotiate-token, nothing written',
        caseRow,
        caseIndex,
      ),
      async () => {
        const { source } = scriptedSource(answer);
        const { target, written } = recordingRequest();
        const error = mintedRefusal(await provider(source).authorize(target));
        assert.equal(error.kind, expected.kind);
        matchObject(error.facts, {
          operation: 'presenting-negotiate-token',
          ...('problem' in expected ? { problem: expected.problem } : {}),
        });
        assert.deepEqual(written, []);
      },
    );
  }
  for (const [caseIndex, caseRow] of (
    ['prepare', 'authorize'] as const
  ).entries()) {
    const moment = caseRow;
    it(
      caseTitle(
        '%s: a source answering mechanism-unsupported is spnego mechanism-unsupported with the moment’s operation',
        caseRow,
        caseIndex,
      ),
      async () => {
        const { source } = scriptedSource(async () => ({
          ok: false,
          problem: 'mechanism-unsupported',
        }));
        const { target, written } = recordingRequest();
        const p = provider(source);
        const outcome =
          moment === 'prepare' ? await p.prepare() : await p.authorize(target);
        const error = mintedRefusal(outcome);
        matchObject(error, {
          kind: 'spnego',
          variant: 'mechanism-unsupported',
          facts: {
            problem: 'mechanism-unsupported',
            operation:
              moment === 'prepare'
                ? 'obtaining-negotiate-token'
                : 'presenting-negotiate-token',
          },
        });
        assert.deepEqual(written, []);
      },
    );
  }
  it('a target whose header throws is Oops, its text nowhere', async () => {
    const { source } = freshSource();
    const { target } = recordingRequest({ throws: true });
    const outcome = await provider(source).authorize(target);
    const error = mintedRefusal(outcome);
    matchObject(error.facts, {
      operation: 'presenting-negotiate-token',
    });
    notContains(JSON.stringify(error), 'SECRET-IN-TARGET');
  });
});

describe('establish()', () => {
  it('is Ok and touches neither the target nor the source', async () => {
    const { source, calls } = freshSource();
    const touched: string[] = [];
    const logon = new Proxy(
      {},
      {
        get(_t, key) {
          touched.push(String(key));
          return () => ({ ok: true });
        },
      },
    );
    assert.deepEqual(await provider(source).establish(logon as never), {
      ok: true,
    });
    assert.deepEqual(touched, []);
    assert.equal(calls.length, 0);
  });
});

describe('rejected()', () => {
  const { source } = freshSource();
  it('a 401 is credential-refused kerberos-ticket', async () => {
    const error = mintedRefusal(
      await provider(source).rejected({
        at: 'request',
        status: 401,
        error: undefined,
      }),
    );
    matchObject(error, {
      kind: 'credential-refused',
      facts: { credential: 'kerberos-ticket', at: 'request' },
    });
  });
  it('a 401 with a Negotiate continuation is the same', async () => {
    const error = mintedRefusal(
      await provider(source).rejected({
        at: 'request',
        status: 401,
        error: {
          response: { headers: { 'www-authenticate': 'Negotiate abc' } },
        },
      }),
    );
    matchObject(error, {
      kind: 'credential-refused',
      facts: { credential: 'kerberos-ticket' },
    });
  });
  for (const [caseIndex, caseRow] of cases([
    [403, 'not-authorized'],
    [500, 'system-failed'],
  ]).entries()) {
    const [status, verdict] = caseRow;
    it(caseTitle('%p is system-refused %p', caseRow, caseIndex), async () => {
      const error = mintedRefusal(
        await provider(source).rejected({
          at: 'request',
          status,
          error: undefined,
        }),
      );
      matchObject(error, {
        kind: 'system-refused',
        facts: { verdict, status },
      });
    });
  }
  it('no status is system-refused unknown', async () => {
    const error = mintedRefusal(
      await provider(source).rejected({ at: 'request', error: undefined }),
    );
    matchObject(error, {
      kind: 'system-refused',
      facts: { verdict: 'unknown' },
    });
  });
  it('asks the source for nothing', async () => {
    const fresh = freshSource();
    await provider(fresh.source).rejected({
      at: 'request',
      status: 401,
      error: undefined,
    });
    assert.equal(fresh.calls.length, 0);
  });
});

describe('abort (no timeout of the package’s choosing)', () => {
  /** A source whose answer is held until the test releases it. */
  function heldSource() {
    let release: (value: unknown) => void = () => undefined;
    const held = scriptedSource(
      () =>
        new Promise((resolve) => {
          release = resolve;
        }),
    );
    return { ...held, release: (value: unknown) => release(value) };
  }
  for (const [caseIndex, caseRow] of (
    ['prepare', 'authorize'] as const
  ).entries()) {
    const moment = caseRow;
    it(
      caseTitle(
        'the parties’ signal reaches the source; its abort ends %s aborted and the late token is never written',
        caseRow,
        caseIndex,
      ),
      async () => {
        const controller = new AbortController();
        const held = heldSource();
        const p = provider(held.source, controller.signal);
        const { target, written } = recordingRequest();
        const outcome =
          moment === 'prepare' ? p.prepare() : p.authorize(target);
        await new Promise((resolve) => setImmediate(resolve));
        const given = held.calls[0]?.options.signal;
        assert.equal(given?.aborted, false);
        controller.abort();
        const error = mintedRefusal(await outcome);
        matchObject(error, {
          kind: 'interactive-login',
          facts: { outcome: 'aborted' },
        });
        assert.equal(given?.aborted, true);
        held.release({ ok: true, token: kerberos() });
        await new Promise((resolve) => setImmediate(resolve));
        assert.deepEqual(written, []);
      },
    );
  }
  it('an attached party: the moment ends when every party has aborted', async () => {
    const first = new AbortController();
    const second = new AbortController();
    const held = heldSource();
    const p = provider(held.source, first.signal);
    p.attach(second.signal);
    const { target, written } = recordingRequest();
    const outcome = p.authorize(target);
    await new Promise((resolve) => setImmediate(resolve));
    first.abort();
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(held.calls[0]?.options.signal?.aborted, false);
    second.abort();
    assert.deepEqual(mintedRefusal(await outcome).facts, {
      outcome: 'aborted',
    });
    held.release({ ok: true, token: kerberos() });
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(written, []);
  });
  it('a source answering after an abort it ignored: aborted, not its answer', async () => {
    const controller = new AbortController();
    const { source } = scriptedSource(async () => {
      controller.abort();
      return { ok: false, problem: 'no-credential' };
    });
    const error = mintedRefusal(
      await provider(source, controller.signal).prepare(),
    );
    assert.deepEqual(error.facts, { outcome: 'aborted' });
  });
  it('without a party, the source is given no signal', async () => {
    const { source, calls } = freshSource();
    await provider(source).prepare();
    assert.equal(calls[0]?.options.signal, undefined);
  });
});
