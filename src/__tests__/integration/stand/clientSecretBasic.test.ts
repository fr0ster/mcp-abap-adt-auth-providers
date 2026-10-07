/**
 * `clientSecretBasic`'s encoding against the stand's two servers — the
 * measurement behind the README's encoding table. Both decode each Basic
 * component per RFC 6749 §2.3.1, so a secret holding `+` and `%` is accepted
 * form-encoded and refused raw (its `/`, which form-decoding leaves as it is,
 * plays no part). UAA is measured through `client_credentials`, Keycloak
 * through the `password` grant. The clients are stand fixtures:
 * `basic_reserved` / `basic:colon` in tests/stand/uaa/config/uaa.yml and
 * `basic-reserved` / `basic:colon` in tests/stand/keycloak/realm-test.json,
 * each with the secret `se+cr%25et/x`.
 *
 * XSUAA is the other way round — raw only, for an id holding `!` and `|` and a
 * secret holding `$`, `=` and `_`: Measured (trial, 2026-10-04, by hand; not
 * in test:xsuaa). It is not part of the stand.
 *
 * Runs only under `npm run test:stand`, which sets UAA_URL and KEYCLOAK_URL;
 * each block's title says why it is skipped otherwise.
 */

import { describe, expect, it } from '@jest/globals';
import { clientSecretBasic } from '../../../clientAuthentication';
import { ClientCredentialsProvider } from '../../../providers/ClientCredentialsProvider';
import { OidcPasswordProvider } from '../../../providers/OidcPasswordProvider';
import { refreshThenLogin } from '../../../renewal';
import { wordsOf } from '../../helpers/minted';

const UAA_URL = process.env.UAA_URL?.replace(/\/+$/, '');
const KEYCLOAK_URL = process.env.KEYCLOAK_URL?.replace(/\/+$/, '');
const describeUaa = UAA_URL ? describe : describe.skip;
const describeKeycloak = KEYCLOAK_URL ? describe : describe.skip;
const unlessSet = (name: string, value: string | undefined): string =>
  value ? '' : ` — skipped: ${name} is not set (npm run test:stand sets it)`;

const SECRET = 'se+cr%25et/x';
const USER = { username: 'tester', password: 'tester' };
const COLON_REFUSAL = {
  ok: false,
  refusal: {
    reason: "the client id contains ':', which raw Basic cannot carry",
    hint: "use encoding: 'form' or clientSecretPost",
  },
};

const claims = (jwt: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString('utf8'));

describeUaa(
  `clientSecretBasic against Cloud Foundry UAA${unlessSet('UAA_URL', UAA_URL)}`,
  () => {
    const provider = (clientId: string, encoding: 'raw' | 'form') =>
      new ClientCredentialsProvider({
        renewal: refreshThenLogin(),
        uaaUrl: UAA_URL as string,
        clientId,
        clientAuthentication: clientSecretBasic(SECRET, { encoding }),
      });

    it("form: a secret holding '+' and '%' gets a token", async () => {
      const tokens = await provider('basic_reserved', 'form').getTokens();
      expect(claims(tokens.authorizationToken).client_id).toBe(
        'basic_reserved',
      );
    });

    it('raw: the same secret is refused by UAA with a 401', async () => {
      await expect(
        provider('basic_reserved', 'raw').getTokens(),
        // D1
      ).rejects.toThrow('the client credentials request failed (HTTP 401');
    });

    it("form: a client id holding ':' gets a token", async () => {
      const tokens = await provider('basic:colon', 'form').getTokens();
      expect(claims(tokens.authorizationToken).client_id).toBe('basic:colon');
    });

    it("raw: a client id holding ':' is refused before anything is sent", async () => {
      expect(wordsOf(await provider('basic:colon', 'raw').prepare())).toEqual(
        COLON_REFUSAL,
      );
    });
  },
);

describeKeycloak(
  `clientSecretBasic against Keycloak${unlessSet('KEYCLOAK_URL', KEYCLOAK_URL)}`,
  () => {
    const provider = (clientId: string, encoding: 'raw' | 'form') =>
      new OidcPasswordProvider({
        renewal: refreshThenLogin(),
        issuerUrl: KEYCLOAK_URL as string,
        clientId,
        ...USER,
        scopes: ['openid'],
        clientAuthentication: clientSecretBasic(SECRET, { encoding }),
      });

    it("form: a secret holding '+' and '%' gets a token", async () => {
      const tokens = await provider('basic-reserved', 'form').getTokens();
      expect(claims(tokens.authorizationToken).azp).toBe('basic-reserved');
    });

    it('raw: the same secret is refused by Keycloak with a 401', async () => {
      await expect(
        provider('basic-reserved', 'raw').getTokens(),
        // D1
      ).rejects.toThrow('the OIDC password grant failed (HTTP 401');
    });

    it("form: a client id holding ':' gets a token", async () => {
      const tokens = await provider('basic:colon', 'form').getTokens();
      expect(claims(tokens.authorizationToken).azp).toBe('basic:colon');
    });

    it("raw: a client id holding ':' is refused before anything is sent", async () => {
      expect(wordsOf(await provider('basic:colon', 'raw').prepare())).toEqual(
        COLON_REFUSAL,
      );
    });
  },
);
