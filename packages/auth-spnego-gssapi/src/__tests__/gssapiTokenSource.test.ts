// The source over a replaced binding: a fake `kerberos` is put in
// `require.cache` and the source module is loaded afresh after it (each case
// gets its own copy, so its once-loaded binding starts empty), so nothing
// native runs. The real binding is loaded only by binding.load.test.ts.

import assert from 'node:assert/strict';
import { Module } from 'node:module';
import {
  afterEach,
  beforeEach,
  describe,
  it,
  type Mock,
  mock,
} from 'node:test';
import type { INegotiateTokenSource } from '@mcp-abap-adt/interfaces-auth';
import {
  cases,
  caseTitle,
  contains,
  containsEqual,
  notContains,
  thrown,
} from './helpers/expectations';

const SPNEGO_OID = 6;
const KRB5_OID = 9;
const SECRET_TEXT = 'SECRET-CACHE /tmp/krb5cc_secret user@REALM';

type Step = (challenge: string) => Promise<unknown>;

interface FakeBinding {
  GSS_MECH_OID_SPNEGO: number;
  GSS_MECH_OID_KRB5: number;
  initializeClient: Mock<
    (
      service: string,
      options: { mechOID: number },
    ) => Promise<{ step: Mock<Step> }>
  >;
  clients: Array<{ step: Mock<Step> }>;
}

function fakeBinding(
  step: (challenge: string) => Promise<unknown> = async () => 'YIIBtoken',
): FakeBinding {
  const clients: FakeBinding['clients'] = [];
  const initializeClient: FakeBinding['initializeClient'] = mock.fn(
    async () => {
      const client = { step: mock.fn<Step>(step) };
      clients.push(client);
      return client;
    },
  );
  return {
    GSS_MECH_OID_SPNEGO: SPNEGO_OID,
    GSS_MECH_OID_KRB5: KRB5_OID,
    initializeClient,
    clients,
  };
}

type Factory = (options: unknown) => INegotiateTokenSource;

const KERBEROS = require.resolve('kerberos');
const SOURCE = require.resolve('../gssapiTokenSource');

/**
 * A fresh copy of the source over `binding`: the fake stands in the cache
 * for `kerberos` (a function stands for a binding whose load throws), and
 * the source is dropped from the cache so it loads, and binds, anew.
 */
function loadWith(binding: FakeBinding | (() => never)): Factory {
  const fake = new Module(KERBEROS);
  fake.filename = KERBEROS;
  fake.loaded = true;
  if (typeof binding === 'function') {
    Object.defineProperty(fake, 'exports', { get: binding });
  } else {
    fake.exports = binding;
  }
  require.cache[KERBEROS] = fake;
  delete require.cache[SOURCE];
  const mod: typeof import('../gssapiTokenSource') = require(SOURCE);
  // The cases hand it what its type refuses, on purpose: called as it is.
  return (options) =>
    Reflect.apply(mod.gssapiTokenSource, undefined, [options]);
}

/** Runs `fn` with `process.platform` reading `platform`, restored after. */
async function onPlatform<T>(
  platform: string,
  fn: () => Promise<T>,
): Promise<T> {
  const saved = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: platform });
  try {
    return await fn();
  } finally {
    if (saved) Object.defineProperty(process, 'platform', saved);
  }
}

afterEach(() => {
  delete require.cache[KERBEROS];
  delete require.cache[SOURCE];
});

describe('gssapiTokenSource options', () => {
  let factory: Factory;
  beforeEach(() => {
    factory = loadWith(fakeBinding());
  });

  for (const [caseIndex, caseRow] of cases([
    [undefined],
    [{}],
    [{ mechanism: undefined }],
    [{ mechanism: 'ntlm' }],
    [{ mechanism: 'SPNEGO' }],
    [{ mechanism: 6 }],
  ]).entries()) {
    const [options] = caseRow;
    it(
      caseTitle(
        'refuses a missing or unknown mechanism (%p), naming only the option',
        caseRow,
        caseIndex,
      ),
      () => {
        let thrown: unknown;
        try {
          factory(options);
        } catch (e) {
          thrown = e;
        }
        assert.ok(thrown instanceof RangeError);
        const message = (thrown as RangeError).message;
        contains(message, 'mechanism');
        notContains(message, 'ntlm');
        notContains(message, 'SPNEGO');
      },
    );
  }

  it('refuses a mechanism behind an accessor without running it', () => {
    const getter = mock.fn(() => 'spnego');
    const options = Object.defineProperty({}, 'mechanism', {
      get: getter,
      enumerable: true,
    });
    assert.throws(() => factory(options), thrown(RangeError));
    assert.equal(getter.mock.callCount(), 0);
  });

  for (const [caseIndex, caseRow] of [
    'principal',
    'flags',
    'mechOID',
    'user',
    'pass',
    'cache',
  ].entries()) {
    const key = caseRow;
    it(
      caseTitle('refuses the unknown option %s, naming it', caseRow, caseIndex),
      () => {
        assert.throws(
          () => factory({ mechanism: 'spnego', [key]: 'x' }),
          thrown(RangeError),
        );
        assert.throws(
          () => factory({ mechanism: 'spnego', [key]: 'x' }),
          thrown(key),
        );
      },
    );
  }

  it('refuses options it cannot read (a throwing Proxy)', () => {
    const hostile = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error(SECRET_TEXT);
        },
      },
    );
    let thrown: unknown;
    try {
      factory(hostile);
    } catch (e) {
      thrown = e;
    }
    assert.ok(thrown instanceof RangeError);
    notContains(String((thrown as Error).message), 'SECRET');
  });

  for (const [caseIndex, caseRow] of (
    ['ownKeys', 'getOwnPropertyDescriptor', 'get', 'has'] as const
  ).entries()) {
    const trap = caseRow;
    it(
      caseTitle(
        'a RangeError carrying a secret from the %s trap is not passed on',
        caseRow,
        caseIndex,
      ),
      () => {
        const secret = new RangeError(SECRET_TEXT);
        const hostile = new Proxy(
          { mechanism: 'spnego' },
          {
            [trap]() {
              throw secret;
            },
          },
        );
        let thrown: unknown;
        try {
          factory(hostile);
        } catch (e) {
          thrown = e;
        }
        // A trap the factory never calls throws nothing; one it calls must not
        // surface the consumer's error or its text.
        if (thrown !== undefined) {
          assert.notEqual(thrown, secret);
          assert.ok(thrown instanceof RangeError);
          notContains(String((thrown as Error).message), 'SECRET');
        }
        if (trap === 'ownKeys' || trap === 'getOwnPropertyDescriptor')
          assert.ok(thrown instanceof RangeError);
      },
    );
  }

  it('accepts each mechanism', () => {
    assert.equal(typeof factory({ mechanism: 'spnego' }).token, 'function');
    assert.equal(typeof factory({ mechanism: 'kerberos' }).token, 'function');
  });
});

describe('gssapiTokenSource token()', () => {
  for (const [caseIndex, caseRow] of cases([
    ['spnego', SPNEGO_OID],
    ['kerberos', KRB5_OID],
  ]).entries()) {
    const [mechanism, oid] = caseRow;
    it(
      caseTitle(
        '%s: initializeClient(principal, { mechOID }), one step(""), the token',
        caseRow,
        caseIndex,
      ),
      async () => {
        const binding = fakeBinding();
        const source = loadWith(binding)({ mechanism });
        // The GSS-API form, as on Linux and macOS, whatever OS runs the test.
        const answer = await onPlatform('linux', () =>
          source.token('HTTP@sap.example.com', {}),
        );
        assert.deepEqual(answer, { ok: true, token: 'YIIBtoken' });
        assert.equal(binding.initializeClient.mock.callCount(), 1);
        containsEqual(
          binding.initializeClient.mock.calls.map((call) => call.arguments),
          ['HTTP@sap.example.com', { mechOID: oid }],
        );
        assert.equal(binding.clients[0]?.step.mock.callCount(), 1);
        containsEqual(
          binding.clients[0]?.step.mock.calls.map((call) => call.arguments) ??
            [],
          [''],
        );
      },
    );
  }

  it('returns a plain native promise', async () => {
    const source = loadWith(fakeBinding())({ mechanism: 'spnego' });
    const answer = source.token('HTTP@sap.example.com', {});
    assert.equal(Object.getPrototypeOf(answer), Promise.prototype);
    await answer;
  });

  it('builds a new client for every call and keeps no token', async () => {
    let n = 0;
    const binding = fakeBinding(async () => `token-${++n}`);
    const source = loadWith(binding)({ mechanism: 'spnego' });
    const first = await source.token('HTTP@sap.example.com', {});
    const second = await source.token('HTTP@sap.example.com', {});
    assert.deepEqual(first, { ok: true, token: 'token-1' });
    assert.deepEqual(second, { ok: true, token: 'token-2' });
    assert.equal(binding.initializeClient.mock.callCount(), 2);
    assert.equal(binding.clients.length, 2);
    assert.equal(binding.clients[0]?.step.mock.callCount(), 1);
    assert.equal(binding.clients[1]?.step.mock.callCount(), 1);
  });

  it('on Windows hands SSPI its form of the name, service/host', async () => {
    const platform = Object.getOwnPropertyDescriptor(process, 'platform');
    Object.defineProperty(process, 'platform', { value: 'win32' });
    try {
      const binding = fakeBinding();
      const source = loadWith(binding)({ mechanism: 'kerberos' });
      await source.token('HTTP@sap.example.com', {});
      containsEqual(
        binding.initializeClient.mock.calls.map((call) => call.arguments),
        ['HTTP/sap.example.com', { mechOID: KRB5_OID }],
      );
    } finally {
      if (platform) Object.defineProperty(process, 'platform', platform);
    }
  });

  it('answers binding-unavailable when the binding cannot be loaded', async () => {
    const source = loadWith(() => {
      throw new Error(
        `Opening library libgssapi_krb5.so.2 failed: ${SECRET_TEXT}`,
      );
    })({ mechanism: 'spnego' });
    const answer = await source.token('HTTP@sap.example.com', {});
    assert.deepEqual(answer, { ok: false, problem: 'binding-unavailable' });
    notContains(JSON.stringify(answer), 'SECRET');
  });

  it('answers binding-unavailable when the module carries no initializeClient', async () => {
    const source = loadWith({
      GSS_MECH_OID_SPNEGO: 6,
    } as unknown as FakeBinding)({
      mechanism: 'spnego',
    });
    assert.deepEqual(await source.token('HTTP@sap.example.com', {}), {
      ok: false,
      problem: 'binding-unavailable',
    });
  });

  it('answers source-failed, not binding-unavailable, when a loaded binding throws', async () => {
    const binding = fakeBinding(async () => {
      throw new Error(SECRET_TEXT);
    });
    const source = loadWith(binding)({ mechanism: 'spnego' });
    assert.deepEqual(await source.token('HTTP@sap.example.com', {}), {
      ok: false,
      problem: 'source-failed',
    });
  });

  it('answers source-failed when initializeClient throws synchronously', async () => {
    const binding = fakeBinding();
    binding.initializeClient.mock.mockImplementation(() => {
      throw new TypeError(SECRET_TEXT);
    });
    const source = loadWith(binding)({ mechanism: 'spnego' });
    assert.deepEqual(await source.token('HTTP@sap.example.com', {}), {
      ok: false,
      problem: 'source-failed',
    });
  });

  it('answers source-failed when step answers no string', async () => {
    const source = loadWith(fakeBinding(async () => undefined))({
      mechanism: 'spnego',
    });
    assert.deepEqual(await source.token('HTTP@sap.example.com', {}), {
      ok: false,
      problem: 'source-failed',
    });
  });

  it('answers source-failed without calling the binding when the signal already aborted', async () => {
    const binding = fakeBinding();
    const source = loadWith(binding)({ mechanism: 'spnego' });
    const signal = AbortSignal.abort();
    assert.deepEqual(await source.token('HTTP@sap.example.com', { signal }), {
      ok: false,
      problem: 'source-failed',
    });
    assert.equal(binding.initializeClient.mock.callCount(), 0);
  });

  it('answers source-failed, the token dropped, when the signal aborts during the call', async () => {
    const controller = new AbortController();
    const binding = fakeBinding(async () => {
      controller.abort();
      return 'late-token';
    });
    const source = loadWith(binding)({ mechanism: 'spnego' });
    const answer = await source.token('HTTP@sap.example.com', {
      signal: controller.signal,
    });
    assert.deepEqual(answer, { ok: false, problem: 'source-failed' });
    notContains(JSON.stringify(answer), 'late-token');
  });

  it('answers source-failed for a principal that is not a string', async () => {
    const binding = fakeBinding();
    const source = loadWith(binding)({ mechanism: 'spnego' });
    assert.deepEqual(await source.token(42 as unknown as string, {}), {
      ok: false,
      problem: 'source-failed',
    });
    assert.equal(binding.initializeClient.mock.callCount(), 0);
  });

  it('answers source-failed for options it cannot read', async () => {
    const binding = fakeBinding();
    const source = loadWith(binding)({ mechanism: 'spnego' });
    const options = Object.defineProperty({}, 'signal', {
      get() {
        throw new Error(SECRET_TEXT);
      },
    });
    assert.deepEqual(await source.token('HTTP@sap.example.com', options), {
      ok: false,
      problem: 'source-failed',
    });
  });

  for (const [caseIndex, caseRow] of cases([
    [
      'No credentials were supplied, or the credentials were unavailable or inaccessible: No Kerberos credentials available (default cache: FILE:/tmp/krb5cc_1000)',
      'no-credential',
    ],
    [
      'Unspecified GSS failure.  Minor code may provide more information: Server not found in Kerberos database',
      'service-unknown',
    ],
    [
      "Unspecified GSS failure.  Minor code may provide more information: Cannot contact any KDC for realm 'EXAMPLE.COM'",
      'kdc-unreachable',
    ],
    [
      'Unspecified GSS failure.  Minor code may provide more information: Clock skew too great',
      'clock-skew',
    ],
  ]).entries()) {
    const [message, problem] = caseRow;
    it(
      caseTitle(
        'maps the binding failure "%s" to %s, its text in no answer',
        caseRow,
        caseIndex,
      ),
      async () => {
        const binding = fakeBinding(async () => {
          throw new Error(message);
        });
        const source = loadWith(binding)({ mechanism: 'spnego' });
        const answer = await source.token('HTTP@sap.example.com', {});
        assert.deepEqual(answer, { ok: false, problem });
        assert.deepEqual(Object.keys(answer).sort(), ['ok', 'problem']);
      },
    );
  }
});
