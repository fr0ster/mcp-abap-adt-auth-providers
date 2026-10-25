import { describe, expect, it } from '@jest/globals';
import { isAuthProviderFailure, readFailure } from '@mcp-abap-adt/auth-errors';
import {
  clientSecretBasic,
  clientSecretPost,
  noClientAuthentication,
} from '../../clientAuthentication';
import { refusedWith, wordsOf } from '../helpers/minted';

const draft = {
  endpoint: 'https://uaa.example/oauth/token',
  clientId: 'my-client',
  grantType: 'client_credentials',
};

describe('noClientAuthentication', () => {
  it('sends client_id in the body and nothing else', async () => {
    const sent = await noClientAuthentication().authenticate(draft);
    expect(sent).toEqual({ parameters: { client_id: 'my-client' } });
  });
  it('presents no TLS material', () => {
    expect(noClientAuthentication().tlsMaterial).toBeUndefined();
  });
});

describe('clientSecretBasic', () => {
  const basic = (value: string) =>
    `Basic ${Buffer.from(value).toString('base64')}`;

  it('raw: sends Basic base64(id:secret) as given, and no body parameters', async () => {
    const sent = await clientSecretBasic('s3+cr%2F:et', {
      encoding: 'raw',
    }).authenticate(draft);
    expect(sent).toEqual({
      headers: { Authorization: basic('my-client:s3+cr%2F:et') },
    });
  });

  it("form: each component form-encoded (space as '+'), then joined and base64'd", async () => {
    const sent = await clientSecretBasic('a b+%/:', {
      encoding: 'form',
    }).authenticate({ ...draft, clientId: 'my client+:x' });
    expect(sent).toEqual({
      headers: { Authorization: basic('my+client%2B%3Ax:a+b%2B%25%2F%3A') },
    });
  });

  it("raw: a client id containing ':' is refused in fixed words, before anything is sent", async () => {
    const auth = clientSecretBasic('top-secret', { encoding: 'raw' });
    const failure = await auth
      .authenticate({ ...draft, clientId: 'my:client' })
      .then(
        () => undefined,
        (error: unknown) => error,
      );
    // An AuthProviderFailure, no longer BasicClientIdError.
    expect(isAuthProviderFailure(failure)).toBe(true);
    expect(String((failure as Error).message)).not.toContain('my:client');
    expect(wordsOf(refusedWith(failure, 'token-request'))).toEqual({
      ok: false,
      refusal: {
        reason: "the client id contains ':', which raw Basic cannot carry",
        hint: "use encoding: 'form' or clientSecretPost",
      },
    });
  });

  it.each<[string, unknown]>([
    ['no options', undefined],
    ['no encoding', {}],
    ['another encoding', { encoding: 'utf8' }],
    ['a non-string encoding', { encoding: 1 }],
  ])(
    '%s: a configuration failure naming encoding, at construction (E19)',
    (_label, options) => {
      let thrown: unknown;
      try {
        // A JavaScript caller can pass anything.
        (clientSecretBasic as (s: string, o: unknown) => unknown)(
          'top-secret',
          options,
        );
      } catch (error) {
        thrown = error;
      }
      // The case, the field and the allowed set.
      expect(readFailure(thrown, 'unfamiliar-error')).toMatchObject({
        kind: 'configuration',
        facts: {
          case: 'basic-encoding-missing',
          fields: ['encoding'],
          allowed: 'basic-encoding',
        },
      });
      expect(wordsOf(refusedWith(thrown, 'token-request'))).toEqual({
        ok: false,
        refusal: {
          reason: "clientSecretBasic needs encoding: 'raw' or 'form'",
          hint: 'check the provider configuration',
        },
      });
    },
  );

  it('presents no TLS material', () => {
    expect(
      clientSecretBasic('x', { encoding: 'raw' }).tlsMaterial,
    ).toBeUndefined();
  });
});

describe('clientSecretPost', () => {
  it('sends client_id and client_secret in the body and no header', async () => {
    const sent = await clientSecretPost('s3cret').authenticate(draft);
    expect(sent).toEqual({
      parameters: { client_id: 'my-client', client_secret: 's3cret' },
    });
  });
  it('presents no TLS material', () => {
    expect(clientSecretPost('x').tlsMaterial).toBeUndefined();
  });
});
