/**
 * No URL reaches a log line: an endpoint is a free value — a discovered one
 * is the server's, a configured one the consumer's (it may carry a
 * credential or a query secret) — so no line names it, `authDebug` absent,
 * `false` or `true`. Against a real socket: discovery documents and
 * configured endpoints carry a marker, line breaks, a BEL and U+202E, and no
 * log line — prompts included — may hold the marker or any control or bidi
 * character. A prompt shows a URL only as `promptableUrl` admits it, and the
 * console device presenter refuses a server's prompt it cannot show.
 */

import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it, jest } from '@jest/globals';
import { readFailure } from '@mcp-abap-adt/auth-errors';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import { promptableText, promptableUrl } from '../../auth/announce';
import { discoverOidc } from '../../auth/oidcDiscovery';
import {
  exchangeSamlAssertion,
  refreshSamlBearerToken,
} from '../../auth/saml2TokenExchange';
import { showUrl } from '../../authorization/presentation';
import { consoleDeviceCodePresenter } from '../../deviceCode/DeviceCodePresenter';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { OidcDeviceFlowProvider } from '../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../providers/OidcPasswordProvider';
import { OidcTokenExchangeProvider } from '../../providers/OidcTokenExchangeProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { refreshThenLogin } from '../../renewal';
import { asOidcResult } from '../../strategies/asOidcResult';
import { staticCodeStrategy } from '../../strategies/codeStrategies';
import {
  manualPasscodeStrategy,
  manualPasteStrategy,
} from '../../strategies/manualStrategies';

const MARKER = 'ENDPOINT-SECRET-7f3a';
/** What a hostile server or configuration puts in a URL. */
const HOSTILE = `${MARKER}\n[forged] line\r\u202Eevil\u0007`;
/**
 * The same without the marker, for the one URL a prompt must show — the
 * authorization URL the user opens: its control characters must still
 * never reach a line.
 */
const CONTROLS = '\n[forged] line\r\u202Eevil\u0007';

/** A control character (C0, DEL, C1) or a bidi control. */
function forbiddenCharacter(value: string): string | undefined {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (
      code < 0x20 ||
      (code >= 0x7f && code <= 0x9f) ||
      (code >= 0x202a && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069) ||
      code === 0x200e ||
      code === 0x200f ||
      code === 0x061c
    ) {
      return `U+${code.toString(16).padStart(4, '0')}`;
    }
  }
  return undefined;
}

/** Every string reachable from a logged argument, keys included. */
function stringsOf(value: unknown, seen = new Set<unknown>()): string[] {
  if (typeof value === 'string') return [value];
  if (value === null || typeof value !== 'object') return [];
  if (seen.has(value)) return [];
  seen.add(value);
  return Object.entries(value).flatMap(([key, inner]) => [
    key,
    ...stringsOf(inner, seen),
  ]);
}

interface Recorder {
  logger: ILogger;
  lines: unknown[][];
}

function recorder(): Recorder {
  const lines: unknown[][] = [];
  const record =
    (level: string) =>
    (...args: unknown[]) => {
      lines.push([level, ...args]);
    };
  return {
    lines,
    logger: {
      debug: record('debug'),
      info: record('info'),
      warn: record('warn'),
      error: record('error'),
    } as ILogger,
  };
}

/** Asserts no line holds the marker or a control/bidi character. */
function expectClean(lines: unknown[][]): void {
  for (const line of lines) {
    for (const text of stringsOf(line)) {
      expect(text).not.toContain(MARKER);
      expect(forbiddenCharacter(text)).toBeUndefined();
    }
  }
}

let answer: 'ok' | 'refuse' = 'ok';
let base = '';
let issuerCount = 0;

const server: Server = createServer((req: IncomingMessage, res) => {
  req.resume();
  req.on('end', () => {
    const url = req.url ?? '';
    res.setHeader('Content-Type', 'application/json');
    if (url.includes('/.well-known/openid-configuration')) {
      const hostile = (name: string) =>
        `${base}/${name}?leak=${HOSTILE}#${HOSTILE}`;
      res.end(
        JSON.stringify({
          issuer: `${base}/${HOSTILE}`,
          authorization_endpoint: `${base}/authorize?x=${CONTROLS}#${CONTROLS}`,
          token_endpoint: hostile('token'),
          device_authorization_endpoint: hostile('device'),
          mtls_endpoint_aliases: { token_endpoint: hostile('mtls') },
        }),
      );
      return;
    }
    if (url.includes('device')) {
      res.end(
        JSON.stringify({
          device_code: 'dc-1',
          user_code: 'AB-CD',
          verification_uri: `${base}/verify`,
          expires_in: 600,
          interval: 0,
        }),
      );
      return;
    }
    if (answer === 'refuse') {
      res.statusCode = 400;
      res.end(
        JSON.stringify({
          error: 'invalid_grant',
          error_description: HOSTILE,
          error_uri: HOSTILE,
        }),
      );
      return;
    }
    res.end(
      JSON.stringify({
        access_token: 'access-token-value',
        refresh_token: 'refresh-token-value',
        expires_in: 3600,
        token_type: 'bearer',
      }),
    );
  });
});

beforeAll(async () => {
  await new Promise<void>((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve()),
  );
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

/** A fresh issuer per provider: the discovery cache is keyed by URL. */
const issuer = () => {
  issuerCount += 1;
  return `${base}/issuer-${issuerCount}`;
};
/** A configured endpoint carrying the marker and the control characters. */
const configured = (name: string) => `${base}/${name}?leak=${HOSTILE}`;

type Build = (
  logger: ILogger,
  authDebug: boolean | undefined,
) => {
  getTokens(): Promise<unknown>;
  refreshTokens?: () => Promise<unknown>;
};

const pasted = (code: string) =>
  manualPasteStrategy({
    redirectUri: 'http://localhost:61001/callback',
    read: async () => code,
  });

const providers: Record<string, Build> = {
  'OIDC password, discovered endpoints': (logger, authDebug) =>
    new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      issuerUrl: issuer(),
      clientId: 'c',
      username: 'u',
      password: 'p',
      logger,
      authDebug,
    }),
  'OIDC password, configured endpoint': (logger, authDebug) =>
    new OidcPasswordProvider({
      renewal: refreshThenLogin(),
      tokenEndpoint: configured('token'),
      clientId: 'c',
      username: 'u',
      password: 'p',
      logger,
      authDebug,
    }),
  'OIDC token exchange, discovered endpoints': (logger, authDebug) =>
    new OidcTokenExchangeProvider({
      renewal: refreshThenLogin(),
      issuerUrl: issuer(),
      clientId: 'c',
      subjectToken: 's',
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      logger,
      authDebug,
    }),
  'OIDC token exchange, configured endpoint': (logger, authDebug) =>
    new OidcTokenExchangeProvider({
      renewal: refreshThenLogin(),
      tokenEndpoint: configured('token'),
      clientId: 'c',
      subjectToken: 's',
      subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
      logger,
      authDebug,
    }),
  'OIDC device flow, discovered endpoints': (logger, authDebug) =>
    new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      issuerUrl: issuer(),
      clientId: 'c',
      presenter: consoleDeviceCodePresenter(logger),
      logger,
      authDebug,
    }),
  'OIDC device flow, configured endpoints': (logger, authDebug) =>
    new OidcDeviceFlowProvider({
      renewal: refreshThenLogin(),
      deviceAuthorizationEndpoint: configured('device'),
      tokenEndpoint: configured('token'),
      clientId: 'c',
      presenter: consoleDeviceCodePresenter(logger),
      logger,
      authDebug,
    }),
  'OIDC browser, discovered endpoints, URL prompted': (logger, authDebug) =>
    new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      issuerUrl: issuer(),
      clientId: 'c',
      authorization: asOidcResult(pasted('code-1')),
      logger,
      authDebug,
    }),
  'OIDC browser, configured endpoints, URL prompted': (logger, authDebug) =>
    new OidcBrowserProvider({
      renewal: refreshThenLogin(),
      authorizationEndpoint: `${base}/authorize?x=${CONTROLS}`,
      tokenEndpoint: configured('token'),
      clientId: 'c',
      authorization: asOidcResult(pasted('code-1')),
      logger,
      authDebug,
    }),
  'client credentials, configured UAA URL': (logger, authDebug) =>
    new ClientCredentialsProvider({
      renewal: refreshThenLogin(),
      uaaUrl: `${base}/uaa-${HOSTILE}`,
      clientId: 'c',
      clientSecret: 'client-secret-value',
      logger,
      authDebug,
    }),
  'authorization code, configured UAA URL': (logger, authDebug) =>
    new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: `${base}/uaa-${HOSTILE}`,
      clientId: 'c',
      clientSecret: 'client-secret-value',
      authorization: staticCodeStrategy({ payload: 'code-1' }),
      logger,
      authDebug,
    }),
  'UAA passcode, configured UAA URL': (logger, authDebug) =>
    new UaaPasscodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: `${base}/uaa-${HOSTILE}`,
      clientId: 'cf',
      authorization: staticCodeStrategy({ payload: 'pc-1' }),
      logger,
      authDebug,
    }),
  'authorization code, UAA URL with controls, URL prompted': (
    logger,
    authDebug,
  ) =>
    new AuthorizationCodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: `${base}/uaa-${CONTROLS}`,
      clientId: 'c',
      clientSecret: 'client-secret-value',
      authorization: pasted('code-1'),
      logger,
      authDebug,
    }),
  'UAA passcode, UAA URL with controls, URL prompted': (logger, authDebug) =>
    new UaaPasscodeProvider({
      renewal: refreshThenLogin(),
      uaaUrl: `${base}/uaa-${CONTROLS}`,
      clientId: 'cf',
      authorization: manualPasscodeStrategy({ read: async () => 'pc-1' }),
      logger,
      authDebug,
    }),
};

describe('no endpoint and no control character in any log line', () => {
  for (const [name, build] of Object.entries(providers)) {
    for (const authDebug of [undefined, false, true]) {
      for (const mode of ['ok', 'refuse'] as const) {
        it(`${name} — authDebug ${String(authDebug)}, server ${mode}`, async () => {
          answer = mode;
          const { logger, lines } = recorder();
          const provider = build(logger, authDebug);
          await provider.getTokens().catch(() => undefined);
          await provider.refreshTokens?.().catch(() => undefined);
          expect(lines.length).toBeGreaterThan(0);
          expectClean(lines);
        });
      }
    }
  }

  it('discovery: a discovery URL carrying the marker is not logged', async () => {
    const { logger, lines } = recorder();
    await discoverOidc(`${base}/disc-${HOSTILE}`, logger).catch(
      () => undefined,
    );
    expect(lines.length).toBeGreaterThan(0);
    expectClean(lines);
  });

  for (const authDebug of [undefined, false, true]) {
    it(`SAML exchange and refresh: the token URL is not logged — authDebug ${String(authDebug)}`, async () => {
      for (const mode of ['ok', 'refuse'] as const) {
        answer = mode;
        const { logger, lines } = recorder();
        const options = authDebug === undefined ? {} : { authDebug };
        await exchangeSamlAssertion(
          'assertion',
          configured('token'),
          'c',
          'client-secret-value',
          logger,
          undefined,
          options,
        ).catch(() => undefined);
        await refreshSamlBearerToken(
          'refresh-token-value',
          configured('token'),
          'c',
          'client-secret-value',
          logger,
          undefined,
          options,
        ).catch(() => undefined);
        expect(lines.length).toBeGreaterThan(0);
        expectClean(lines);
      }
    });
  }

  it('showUrl prompts no hostile URL: the URL on stderr as admitted, the logger fixed words', async () => {
    const written: string[] = [];
    const spy = jest
      .spyOn(process.stderr, 'write')
      .mockImplementation((chunk: unknown) => {
        written.push(String(chunk));
        return true;
      });
    try {
      const { logger, lines } = recorder();
      showUrl().present(`${base}/authorize?x=${CONTROLS}`, {
        redirectUri: `http://localhost:1/callback?${CONTROLS}`,
        waitingOn: `http://localhost:1/callback?${CONTROLS}`,
        routeHint: `tunnel${CONTROLS}`,
        signal: new AbortController().signal,
        logger,
      });
      // One line per write: its own line break is the prompt's, not forged.
      const shownLines = written.map((chunk) =>
        chunk.endsWith('\n') ? chunk.slice(0, -1) : chunk,
      );
      expectClean([shownLines, ...lines]);
      // The admitted serialisation still reaches the user, on stderr only.
      expect(written.join('')).toContain(`${base}/authorize?x=`);
      expect(JSON.stringify(lines)).not.toContain('/authorize');
      // A URL whose host the serialiser keeps hostile is not shown at all.
      written.length = 0;
      const second = recorder();
      showUrl().present('javascript:alert(1)', {
        redirectUri: undefined,
        signal: new AbortController().signal,
        logger: second.logger,
      });
      const all = `${written.join('')}${JSON.stringify(second.lines)}`;
      expect(all).not.toContain('javascript');
      expect(all).toContain('is not an http(s) URL');
    } finally {
      spy.mockRestore();
    }
  });
});

describe('promptableUrl / promptableText', () => {
  it('admit only http(s) URLs serialised to printable ASCII', () => {
    expect(promptableUrl('https://idp.example/a?b=c')).toBe(
      'https://idp.example/a?b=c',
    );
    const shown = promptableUrl(`https://idp.example/a?b=${HOSTILE}`);
    expect(shown).toBeDefined();
    expect(forbiddenCharacter(shown ?? '')).toBeUndefined();
    expect(promptableUrl('file:///etc/passwd')).toBeUndefined();
    expect(promptableUrl('not a url')).toBeUndefined();
    expect(promptableUrl(42)).toBeUndefined();
  });

  it('admit only printable ASCII text', () => {
    expect(promptableText(' AB-CD ')).toBe('AB-CD');
    expect(promptableText('AB CD')).toBe('AB CD');
    expect(promptableText('AB\nCD')).toBeUndefined();
    expect(promptableText('AB\u202ECD')).toBeUndefined();
    expect(promptableText('')).toBeUndefined();
    expect(promptableText(7)).toBeUndefined();
  });
});

describe('the console device presenter shows only what it can show', () => {
  it('a hostile user code: nothing shown, device-code-not-shown', async () => {
    const { logger, lines } = recorder();
    const thrown = await consoleDeviceCodePresenter(logger)
      .present({
        verificationUri: 'https://idp.example/device',
        userCode: `AB\n[forged] ${MARKER}`,
      })
      .then(
        () => undefined,
        (error: unknown) => error,
      );
    expect(readFailure(thrown, 'presenting-device-code').kind).toBe(
      'interactive-login',
    );
    expect(lines).toEqual([]);
  });

  it('a verification URI that is no http(s) URL: nothing shown', async () => {
    const { logger, lines } = recorder();
    const thrown = await consoleDeviceCodePresenter(logger)
      .present({ verificationUri: `javascript:${MARKER}`, userCode: 'AB-CD' })
      .then(
        () => undefined,
        (error: unknown) => error,
      );
    expect(readFailure(thrown, 'presenting-device-code').facts).toEqual({
      outcome: 'device-code-not-shown',
    });
    expect(lines).toEqual([]);
  });

  it('a hostile complete URI is left out; the rest is shown, escaped', async () => {
    const { logger, lines } = recorder();
    await consoleDeviceCodePresenter(logger).present({
      verificationUri: `https://idp.example/device?x=${CONTROLS}`,
      verificationUriComplete: `javascript:${HOSTILE}`,
      userCode: 'AB-CD',
    });
    expectClean(lines);
    const text = stringsOf(lines).join('\n');
    expect(text).toContain('Enter code: AB-CD');
    expect(text).not.toContain('Or use');
  });
});
