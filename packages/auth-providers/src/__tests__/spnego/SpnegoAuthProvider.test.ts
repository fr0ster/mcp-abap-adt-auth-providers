import { describe, expect, it } from '@jest/globals';
import type {
  INegotiateTokenSource,
  IRequestTarget,
  NegotiateTokenOptions,
} from '@mcp-abap-adt/interfaces-auth';
import { NEGOTIATE_SOURCE_PROBLEMS } from '@mcp-abap-adt/interfaces-auth';
import { SpnegoAuthProvider } from '../../spnego/SpnegoAuthProvider';
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
/** NTLM wrapped in SPNEGO: what Windows' Negotiate falls back to. */
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
  it('requires servicePrincipal', () => {
    const c = configurationOf(
      thrownBy(() => new SpnegoAuthProvider({ tokenSource: source } as never)),
    );
    expect(c).toMatchObject({
      case: 'required-fields-missing',
      fields: ['servicePrincipal'],
    });
  });
  it('requires tokenSource', () => {
    const c = configurationOf(
      thrownBy(
        () => new SpnegoAuthProvider({ servicePrincipal: SPN } as never),
      ),
    );
    expect(c).toMatchObject({
      case: 'required-fields-missing',
      fields: ['tokenSource'],
    });
  });
  it.each([
    ['an object without token', {}],
    ['token not a function', { token: 'x' }],
    ['a function', () => undefined],
    ['a string', 'source'],
  ])('a tokenSource that is %s is missing', (_label, tokenSource) => {
    const c = configurationOf(
      thrownBy(
        () =>
          new SpnegoAuthProvider({
            servicePrincipal: SPN,
            tokenSource: tokenSource as never,
          }),
      ),
    );
    expect(c).toMatchObject({
      case: 'required-fields-missing',
      fields: ['tokenSource'],
    });
  });
  it('a tokenSource whose token is a throwing getter is missing, its text nowhere', () => {
    const tokenSource = Object.defineProperty({}, 'token', {
      get() {
        throw new Error('GETTER-SECRET');
      },
    });
    const thrown = thrownBy(
      () =>
        new SpnegoAuthProvider({
          servicePrincipal: SPN,
          tokenSource: tokenSource as never,
        }),
    );
    expect(configurationOf(thrown).fields).toEqual(['tokenSource']);
    expect(JSON.stringify(thrown)).not.toContain('GETTER-SECRET');
  });
  it.each(['HTTP@sap.example.com', 'HTTP@h', 'host-2@a-b.c', 'HTTP@A1.b2-c.D'])(
    'accepts %p',
    (servicePrincipal) => {
      expect(
        () => new SpnegoAuthProvider({ servicePrincipal, tokenSource: source }),
      ).not.toThrow();
    },
  );
  it.each([
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
  ])('refuses %p as invalid-value', (servicePrincipal) => {
    const c = configurationOf(
      thrownBy(
        () => new SpnegoAuthProvider({ servicePrincipal, tokenSource: source }),
      ),
    );
    expect(c).toMatchObject({
      case: 'invalid-value',
      fields: ['servicePrincipal'],
    });
    if (servicePrincipal !== '') {
      expect(c.reason).not.toContain(servicePrincipal);
    }
  });
  it.each([
    ['a number', 42],
    ['an object', {}],
  ])('refuses a servicePrincipal that is %s as invalid-value', (_l, value) => {
    const c = configurationOf(
      thrownBy(
        () =>
          new SpnegoAuthProvider({
            servicePrincipal: value as never,
            tokenSource: source,
          }),
      ),
    );
    expect(c.case).toBe('invalid-value');
  });
  it('kind is spnego', () => {
    expect(provider(source).kind).toBe('spnego');
  });
});

describe('prepare()', () => {
  it('asks the source once, with the service principal and a signal option', async () => {
    const { source, calls } = freshSource();
    await expect(provider(source).prepare()).resolves.toEqual({ ok: true });
    expect(calls).toHaveLength(1);
    expect(calls[0]?.servicePrincipal).toBe(SPN);
    expect(Object.keys(calls[0]?.options ?? {})).toEqual(['signal']);
  });
  it('a SPNEGO token with Kerberos first is Ok', async () => {
    const token = b64(
      negTokenInit({ mechs: [OID_KRB5, OID_NTLM], mechToken: gssKerberos() }),
    );
    const { source } = scriptedSource(async () => ({ ok: true, token }));
    await expect(provider(source).prepare()).resolves.toEqual({ ok: true });
  });
  it.each(NEGOTIATE_SOURCE_PROBLEMS)(
    'a source problem %p is spnego with that problem',
    async (problem) => {
      const { source } = scriptedSource(async () => ({ ok: false, problem }));
      const error = mintedRefusal(await provider(source).prepare());
      expect(error).toMatchObject({
        kind: 'spnego',
        variant: problem,
        facts: { problem, operation: 'obtaining-negotiate-token' },
      });
    },
  );
  it.each([
    ['raw NTLM', b64(NTLM_NEGOTIATE)],
    ['NTLM inside SPNEGO', NTLM_IN_SPNEGO],
  ])('%s is ntlm-token', async (_label, token) => {
    const { source } = scriptedSource(async () => ({ ok: true, token }));
    const error = mintedRefusal(await provider(source).prepare());
    expect(error.facts).toEqual({
      problem: 'ntlm-token',
      operation: 'obtaining-negotiate-token',
    });
  });
  it.each([
    ['garbage', 'not-base64!'],
    ['an empty token', ''],
    ['base64 of nothing known', b64(Buffer.from('hello world'))],
  ])('%s is token-unreadable', async (_label, token) => {
    const { source } = scriptedSource(async () => ({ ok: true, token }));
    const error = mintedRefusal(await provider(source).prepare());
    expect(error.facts).toEqual({
      problem: 'token-unreadable',
      operation: 'obtaining-negotiate-token',
    });
  });
  it.each<[string, () => unknown]>([
    [
      'a throw',
      () => {
        throw new Error('SOURCE-SECRET');
      },
    ],
    ['a rejection', async () => Promise.reject(new Error('SOURCE-SECRET'))],
    ['{ ok: true } without a token', async () => ({ ok: true })],
    [
      '{ ok: true } with a non-string token',
      async () => ({ ok: true, token: 42 }),
    ],
    [
      'an unknown problem',
      async () => ({ ok: false, problem: 'SOURCE-SECRET' }),
    ],
    [
      'a problem only the provider names',
      async () => ({ ok: false, problem: 'ntlm-token' }),
    ],
    ['ok not a boolean', async () => ({ ok: 'yes', token: kerberos() })],
    ['a non-object', async () => 'SOURCE-SECRET'],
    ['nothing', async () => undefined],
    ['a synchronous non-promise', () => ({ ok: true, token: kerberos() })],
    [
      'an answer with throwing getters',
      async () =>
        Object.defineProperty({}, 'ok', {
          get() {
            throw new Error('SOURCE-SECRET');
          },
        }),
    ],
  ])('%s is unknown with the operation', async (_label, answer) => {
    const { source } = scriptedSource(answer);
    const outcome = await provider(source).prepare();
    const error = mintedRefusal(outcome);
    expect(error).toMatchObject({
      kind: 'unknown',
      facts: { operation: 'obtaining-negotiate-token' },
    });
    expect(JSON.stringify(error)).not.toContain('SOURCE-SECRET');
  });
  it('a foreign thenable is unknown, its then never called', async () => {
    let called = false;
    const { source } = scriptedSource(() => ({
      // biome-ignore lint/suspicious/noThenProperty: the hostile case under test
      then(resolve: (v: unknown) => void) {
        called = true;
        resolve({ ok: true, token: kerberos() });
      },
    }));
    const error = mintedRefusal(await provider(source).prepare());
    expect(error).toMatchObject({
      kind: 'unknown',
      facts: { operation: 'obtaining-negotiate-token' },
    });
    await new Promise((resolve) => setImmediate(resolve));
    expect(called).toBe(false);
  });
  it('a native promise with an own then is unknown, its then never called', async () => {
    let called = false;
    const { source } = scriptedSource(() => {
      const p = Promise.resolve({ ok: true, token: kerberos() });
      Object.defineProperty(p, 'then', {
        value: () => {
          called = true;
        },
      });
      return p;
    });
    const error = mintedRefusal(await provider(source).prepare());
    expect(error.kind).toBe('unknown');
    expect(called).toBe(false);
  });
  it('a source whose token turned into a non-function later is unknown', async () => {
    const source = { token: async () => ({ ok: true, token: kerberos() }) };
    const p = provider(source as INegotiateTokenSource);
    (source as { token: unknown }).token = 'gone';
    expect(mintedRefusal(await p.prepare()).kind).toBe('unknown');
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
    expect(source.seen).toBe(source);
  });
});

describe('authorize()', () => {
  it('asks the source for a new token every time, never reusing one', async () => {
    const { source, calls } = freshSource();
    const p = provider(source);
    await p.prepare();
    const { target, written } = recordingRequest();
    for (let i = 0; i < 3; i += 1) {
      await expect(p.authorize(target)).resolves.toEqual({ ok: true });
    }
    expect(calls).toHaveLength(4);
    expect(written).toEqual([
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
    expect(calls).toHaveLength(2);
    expect(written.map(([, v]) => v)).toEqual([
      `Negotiate ${kerberos(1)}`,
      `Negotiate ${kerberos(2)}`,
    ]);
    expect(calls.every((c) => c.servicePrincipal === SPN)).toBe(true);
  });
  it.each<[string, () => unknown, Record<string, string>]>([
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
  ])(
    '%s: a refusal naming presenting-negotiate-token, nothing written',
    async (_l, answer, expected) => {
      const { source } = scriptedSource(answer);
      const { target, written } = recordingRequest();
      const error = mintedRefusal(await provider(source).authorize(target));
      expect(error.kind).toBe(expected.kind);
      expect(error.facts).toMatchObject({
        operation: 'presenting-negotiate-token',
        ...(expected.problem ? { problem: expected.problem } : {}),
      });
      expect(written).toEqual([]);
    },
  );
  it('a target whose header throws is Oops, its text nowhere', async () => {
    const { source } = freshSource();
    const { target } = recordingRequest({ throws: true });
    const outcome = await provider(source).authorize(target);
    const error = mintedRefusal(outcome);
    expect(error.facts).toMatchObject({
      operation: 'presenting-negotiate-token',
    });
    expect(JSON.stringify(error)).not.toContain('SECRET-IN-TARGET');
  });
  it('a target whose header answers a rejecting promise raises nothing', async () => {
    const { source } = freshSource();
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    process.on('unhandledRejection', onUnhandled);
    try {
      const target = {
        header: () => Promise.reject(new Error('async target')),
        cookies: () => undefined,
      } as unknown as IRequestTarget;
      await expect(provider(source).authorize(target)).resolves.toEqual({
        ok: true,
      });
      await new Promise((resolve) => setImmediate(resolve));
      expect(unhandled).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
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
    await expect(provider(source).establish(logon as never)).resolves.toEqual({
      ok: true,
    });
    expect(touched).toEqual([]);
    expect(calls).toHaveLength(0);
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
    expect(error).toMatchObject({
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
    expect(error).toMatchObject({
      kind: 'credential-refused',
      facts: { credential: 'kerberos-ticket' },
    });
  });
  it.each([
    [403, 'not-authorized'],
    [500, 'system-failed'],
  ])('%p is system-refused %p', async (status, verdict) => {
    const error = mintedRefusal(
      await provider(source).rejected({
        at: 'request',
        status,
        error: undefined,
      }),
    );
    expect(error).toMatchObject({
      kind: 'system-refused',
      facts: { verdict, status },
    });
  });
  it('no status is system-refused unknown', async () => {
    const error = mintedRefusal(
      await provider(source).rejected({ at: 'request', error: undefined }),
    );
    expect(error).toMatchObject({
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
    expect(fresh.calls).toHaveLength(0);
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
  it.each(['prepare', 'authorize'] as const)(
    'the parties’ signal reaches the source; its abort ends %s aborted and the late token is never written',
    async (moment) => {
      const controller = new AbortController();
      const held = heldSource();
      const p = provider(held.source, controller.signal);
      const { target, written } = recordingRequest();
      const outcome = moment === 'prepare' ? p.prepare() : p.authorize(target);
      await new Promise((resolve) => setImmediate(resolve));
      const given = held.calls[0]?.options.signal;
      expect(given?.aborted).toBe(false);
      controller.abort();
      const error = mintedRefusal(await outcome);
      expect(error).toMatchObject({
        kind: 'interactive-login',
        facts: { outcome: 'aborted' },
      });
      expect(given?.aborted).toBe(true);
      held.release({ ok: true, token: kerberos() });
      await new Promise((resolve) => setImmediate(resolve));
      expect(written).toEqual([]);
    },
  );
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
    expect(held.calls[0]?.options.signal?.aborted).toBe(false);
    second.abort();
    expect(mintedRefusal(await outcome).facts).toEqual({ outcome: 'aborted' });
    held.release({ ok: true, token: kerberos() });
    await new Promise((resolve) => setImmediate(resolve));
    expect(written).toEqual([]);
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
    expect(error.facts).toEqual({ outcome: 'aborted' });
  });
  it('without a party, the source is given no signal', async () => {
    const { source, calls } = freshSource();
    await provider(source).prepare();
    expect(calls[0]?.options.signal).toBeUndefined();
  });
});
