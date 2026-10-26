/**
 * Options are a typed copy: an exported constructor or factory takes
 * `{ ...options }` once, so a getter on the options object runs exactly
 * once, at creation, and never again when a moment runs. (A snapshot of own
 * data that never ran a getter read it as absent: the count was 0.)
 */

import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from '@jest/globals';
import type { INegotiateTokenSource } from '@mcp-abap-adt/interfaces-auth';
import { composeAuthorization } from '../../authorization/compose';
import { oauthCode } from '../../authorization/protocol';
import { privateKeyJwt } from '../../clientAuthentication/privateKeyJwt';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { refreshThenLogin } from '../../renewal';
import { SpnegoAuthProvider } from '../../spnego/SpnegoAuthProvider';
import {
  recordingPresentation,
  scriptedTransport,
} from '../helpers/composedParts';

/** `base` with `field` a getter that counts its reads. */
function counting<T extends object>(
  base: T,
  field: keyof T,
): { options: T; reads: () => number } {
  let count = 0;
  const options = { ...base };
  Object.defineProperty(options, field, {
    enumerable: true,
    get: () => {
      count += 1;
      return base[field];
    },
  });
  return { options, reads: () => count };
}

describe('options getter runs once, at creation', () => {
  it('ClientCredentialsProvider', async () => {
    const { options, reads } = counting(
      {
        renewal: refreshThenLogin(),
        uaaUrl: 'https://uaa.example',
        clientId: 'c',
        clientSecret: 's',
      },
      'clientId',
    );
    const provider = new ClientCredentialsProvider(options);
    expect(reads()).toBe(1);
    // A moment: a logon decides on the token held and obtains nothing.
    await provider.establish({
      header: () => ({ ok: true }),
      cookies: () => ({ ok: true }),
      logonParameters: () => ({ ok: true }),
      tlsMaterial: () => ({ ok: true }),
    } as never);
    expect(reads()).toBe(1);
  });

  it('composeAuthorization', async () => {
    const scripted = scriptedTransport({
      redirectUri: 'http://127.0.0.1:61099/callback',
    });
    const { presentation } = recordingPresentation();
    const { options, reads } = counting(
      {
        presentation,
        transport: scripted.transport,
        protocol: oauthCode(),
        endpoint: '/callback',
      },
      'endpoint',
    );
    const strategy = composeAuthorization(options);
    expect(reads()).toBe(1);
    const aborted = AbortSignal.abort();
    await strategy
      .authorize({
        buildAuthorizationUrl: async () =>
          'https://idp.example/a?state=abcdefghijklmnopqrstuvwxyz0123456789',
        signal: aborted,
      } as never)
      .catch(() => undefined);
    expect(reads()).toBe(1);
  });

  it('privateKeyJwt', async () => {
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const { options, reads } = counting(
      { key: privateKey, algorithm: 'RS256' as const },
      'algorithm',
    );
    const authentication = privateKeyJwt(options);
    expect(reads()).toBe(1);
    await authentication.authenticate({
      endpoint: 'https://uaa.example/oauth/token',
      clientId: 'c',
      grantType: 'client_credentials',
    } as never);
    expect(reads()).toBe(1);
  });

  it('SpnegoAuthProvider', async () => {
    const source: INegotiateTokenSource = {
      token: async () => ({ ok: false, problem: 'no-credential' }),
    } as never;
    const { options, reads } = counting(
      { servicePrincipal: 'HTTP@sap.example.com', tokenSource: source },
      'servicePrincipal',
    );
    const provider = new SpnegoAuthProvider(options);
    expect(reads()).toBe(1);
    await provider.prepare();
    expect(reads()).toBe(1);
  });
});
