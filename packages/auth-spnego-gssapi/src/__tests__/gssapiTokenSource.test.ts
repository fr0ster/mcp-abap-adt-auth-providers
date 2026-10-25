// The source over a replaced binding: `kerberos` is mocked at its import
// boundary (jest.doMock before the source module is loaded), so nothing native
// runs. The real binding is loaded only by binding.load.test.ts.
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  jest,
} from '@jest/globals';
import type { INegotiateTokenSource } from '@mcp-abap-adt/interfaces-auth';

const SPNEGO_OID = 6;
const KRB5_OID = 9;
const SECRET_TEXT = 'SECRET-CACHE /tmp/krb5cc_secret user@REALM';

interface FakeBinding {
  GSS_MECH_OID_SPNEGO: number;
  GSS_MECH_OID_KRB5: number;
  initializeClient: jest.Mock<(...args: any[]) => any>;
  clients: Array<{ step: jest.Mock<(...args: any[]) => any> }>;
}

function fakeBinding(
  step: (challenge: string) => Promise<unknown> = async () => 'YIIBtoken',
): FakeBinding {
  const clients: FakeBinding['clients'] = [];
  const initializeClient = jest.fn<(...args: any[]) => any>(async () => {
    const client = { step: jest.fn<(...args: any[]) => any>(step) };
    clients.push(client);
    return client;
  });
  return {
    GSS_MECH_OID_SPNEGO: SPNEGO_OID,
    GSS_MECH_OID_KRB5: KRB5_OID,
    initializeClient,
    clients,
  };
}

type Factory = (options: unknown) => INegotiateTokenSource;

function loadWith(binding: FakeBinding | (() => never)): Factory {
  jest.resetModules();
  jest.doMock('kerberos', () =>
    typeof binding === 'function' ? binding() : binding,
  );
  const mod = require('../gssapiTokenSource') as { gssapiTokenSource: Factory };
  return mod.gssapiTokenSource;
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
  jest.dontMock('kerberos');
});

describe('gssapiTokenSource options', () => {
  let factory: Factory;
  beforeEach(() => {
    factory = loadWith(fakeBinding());
  });

  it.each([
    [undefined],
    [{}],
    [{ mechanism: undefined }],
    [{ mechanism: 'ntlm' }],
    [{ mechanism: 'SPNEGO' }],
    [{ mechanism: 6 }],
  ])(
    'refuses a missing or unknown mechanism (%p), naming only the option',
    (options) => {
      let thrown: unknown;
      try {
        factory(options);
      } catch (e) {
        thrown = e;
      }
      expect(thrown).toBeInstanceOf(RangeError);
      const message = (thrown as RangeError).message;
      expect(message).toContain('mechanism');
      expect(message).not.toContain('ntlm');
      expect(message).not.toContain('SPNEGO');
    },
  );

  it('refuses a mechanism behind an accessor without running it', () => {
    const getter = jest.fn(() => 'spnego');
    const options = Object.defineProperty({}, 'mechanism', {
      get: getter,
      enumerable: true,
    });
    expect(() => factory(options)).toThrow(RangeError);
    expect(getter).not.toHaveBeenCalled();
  });

  it.each(['principal', 'flags', 'mechOID', 'user', 'pass', 'cache'])(
    'refuses the unknown option %s, naming it',
    (key) => {
      expect(() => factory({ mechanism: 'spnego', [key]: 'x' })).toThrow(
        RangeError,
      );
      expect(() => factory({ mechanism: 'spnego', [key]: 'x' })).toThrow(key);
    },
  );

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
    expect(thrown).toBeInstanceOf(RangeError);
    expect(String((thrown as Error).message)).not.toContain('SECRET');
  });

  it.each(['ownKeys', 'getOwnPropertyDescriptor', 'get', 'has'] as const)(
    'a RangeError carrying a secret from the %s trap is not passed on',
    (trap) => {
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
        expect(thrown).not.toBe(secret);
        expect(thrown).toBeInstanceOf(RangeError);
        expect(String((thrown as Error).message)).not.toContain('SECRET');
      }
      if (trap === 'ownKeys' || trap === 'getOwnPropertyDescriptor')
        expect(thrown).toBeInstanceOf(RangeError);
    },
  );

  it('accepts each mechanism', () => {
    expect(typeof factory({ mechanism: 'spnego' }).token).toBe('function');
    expect(typeof factory({ mechanism: 'kerberos' }).token).toBe('function');
  });
});

describe('gssapiTokenSource token()', () => {
  it.each([
    ['spnego', SPNEGO_OID],
    ['kerberos', KRB5_OID],
  ])(
    '%s: initializeClient(principal, { mechOID }), one step(""), the token',
    async (mechanism, oid) => {
      const binding = fakeBinding();
      const source = loadWith(binding)({ mechanism });
      // The GSS-API form, as on Linux and macOS, whatever OS runs the test.
      const answer = await onPlatform('linux', () =>
        source.token('HTTP@sap.example.com', {}),
      );
      expect(answer).toEqual({ ok: true, token: 'YIIBtoken' });
      expect(binding.initializeClient).toHaveBeenCalledTimes(1);
      expect(binding.initializeClient).toHaveBeenCalledWith(
        'HTTP@sap.example.com',
        {
          mechOID: oid,
        },
      );
      expect(binding.clients[0]?.step).toHaveBeenCalledTimes(1);
      expect(binding.clients[0]?.step).toHaveBeenCalledWith('');
    },
  );

  it('returns a plain native promise', () => {
    const source = loadWith(fakeBinding())({ mechanism: 'spnego' });
    const answer = source.token('HTTP@sap.example.com', {});
    expect(Object.getPrototypeOf(answer)).toBe(Promise.prototype);
    return answer;
  });

  it('builds a new client for every call and keeps no token', async () => {
    let n = 0;
    const binding = fakeBinding(async () => `token-${++n}`);
    const source = loadWith(binding)({ mechanism: 'spnego' });
    const first = await source.token('HTTP@sap.example.com', {});
    const second = await source.token('HTTP@sap.example.com', {});
    expect(first).toEqual({ ok: true, token: 'token-1' });
    expect(second).toEqual({ ok: true, token: 'token-2' });
    expect(binding.initializeClient).toHaveBeenCalledTimes(2);
    expect(binding.clients).toHaveLength(2);
    expect(binding.clients[0]?.step).toHaveBeenCalledTimes(1);
    expect(binding.clients[1]?.step).toHaveBeenCalledTimes(1);
  });

  it('on Windows hands SSPI its form of the name, service/host', async () => {
    const platform = Object.getOwnPropertyDescriptor(process, 'platform');
    Object.defineProperty(process, 'platform', { value: 'win32' });
    try {
      const binding = fakeBinding();
      const source = loadWith(binding)({ mechanism: 'kerberos' });
      await source.token('HTTP@sap.example.com', {});
      expect(binding.initializeClient).toHaveBeenCalledWith(
        'HTTP/sap.example.com',
        {
          mechOID: KRB5_OID,
        },
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
    expect(answer).toEqual({ ok: false, problem: 'binding-unavailable' });
    expect(JSON.stringify(answer)).not.toContain('SECRET');
  });

  it('answers binding-unavailable when the module carries no initializeClient', async () => {
    const source = loadWith({
      GSS_MECH_OID_SPNEGO: 6,
    } as unknown as FakeBinding)({
      mechanism: 'spnego',
    });
    expect(await source.token('HTTP@sap.example.com', {})).toEqual({
      ok: false,
      problem: 'binding-unavailable',
    });
  });

  it('answers source-failed, not binding-unavailable, when a loaded binding throws', async () => {
    const binding = fakeBinding(async () => {
      throw new Error(SECRET_TEXT);
    });
    const source = loadWith(binding)({ mechanism: 'spnego' });
    expect(await source.token('HTTP@sap.example.com', {})).toEqual({
      ok: false,
      problem: 'source-failed',
    });
  });

  it('answers source-failed when initializeClient throws synchronously', async () => {
    const binding = fakeBinding();
    binding.initializeClient.mockImplementation(() => {
      throw new TypeError(SECRET_TEXT);
    });
    const source = loadWith(binding)({ mechanism: 'spnego' });
    expect(await source.token('HTTP@sap.example.com', {})).toEqual({
      ok: false,
      problem: 'source-failed',
    });
  });

  it('answers source-failed when step answers no string', async () => {
    const source = loadWith(fakeBinding(async () => undefined))({
      mechanism: 'spnego',
    });
    expect(await source.token('HTTP@sap.example.com', {})).toEqual({
      ok: false,
      problem: 'source-failed',
    });
  });

  it('answers source-failed without calling the binding when the signal already aborted', async () => {
    const binding = fakeBinding();
    const source = loadWith(binding)({ mechanism: 'spnego' });
    const signal = AbortSignal.abort();
    expect(await source.token('HTTP@sap.example.com', { signal })).toEqual({
      ok: false,
      problem: 'source-failed',
    });
    expect(binding.initializeClient).not.toHaveBeenCalled();
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
    expect(answer).toEqual({ ok: false, problem: 'source-failed' });
    expect(JSON.stringify(answer)).not.toContain('late-token');
  });

  it('answers source-failed for a principal that is not a string', async () => {
    const binding = fakeBinding();
    const source = loadWith(binding)({ mechanism: 'spnego' });
    expect(await source.token(42 as unknown as string, {})).toEqual({
      ok: false,
      problem: 'source-failed',
    });
    expect(binding.initializeClient).not.toHaveBeenCalled();
  });

  it('answers source-failed for options it cannot read', async () => {
    const binding = fakeBinding();
    const source = loadWith(binding)({ mechanism: 'spnego' });
    const options = Object.defineProperty({}, 'signal', {
      get() {
        throw new Error(SECRET_TEXT);
      },
    });
    expect(await source.token('HTTP@sap.example.com', options)).toEqual({
      ok: false,
      problem: 'source-failed',
    });
  });

  it.each([
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
  ])(
    'maps the binding failure "%s" to %s, its text in no answer',
    async (message, problem) => {
      const binding = fakeBinding(async () => {
        throw new Error(message);
      });
      const source = loadWith(binding)({ mechanism: 'spnego' });
      const answer = await source.token('HTTP@sap.example.com', {});
      expect(answer).toEqual({ ok: false, problem });
      expect(Object.keys(answer).sort()).toEqual(['ok', 'problem']);
    },
  );
});
