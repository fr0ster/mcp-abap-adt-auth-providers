/**
 * Client certificates and signed client assertions against the stand:
 * Keycloak over HTTPS (tests/stand/compose.yaml, the `test` realm's clients
 * `mtls`, `jwt` and `x509-login`) and UAA (`jwt_client` in
 * tests/stand/uaa/config/uaa.yml). The certificates and the signing key are
 * the throwaway fixtures in tests/stand/keycloak/tls/.
 *
 * Runs only under `npm run test:stand`, which sets KEYCLOAK_HTTPS_URL and
 * UAA_URL, and NODE_EXTRA_CA_CERTS to the stand's CA — the only trust the
 * suites get: no provider here is given a `ca`. Each block states, in its
 * title, why it is skipped when its server is not named.
 *
 * Keycloak asks for a client certificate on HTTPS without requiring one, so a
 * request that presents none, or presents another, reaches it and is refused
 * by the rule under test — not by the handshake.
 */

import assert from 'node:assert/strict';
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Agent, request } from 'node:https';
import { join } from 'node:path';
import { before, describe, it } from 'node:test';
import { inspect } from 'node:util';
import type { ICertificateMaterial } from '@mcp-abap-adt/interfaces-auth';
import type { ILogger } from '@mcp-abap-adt/interfaces-utils';
import {
  privateKeyJwt,
  tlsClientCertificate,
} from '../../../clientAuthentication';
import { CertificateAuthProvider } from '../../../credentials/CertificateAuthProvider';
import { ClientCredentialsProvider } from '../../../providers/ClientCredentialsProvider';
import { OidcDeviceFlowProvider } from '../../../providers/OidcDeviceFlowProvider';
import { OidcPasswordProvider } from '../../../providers/OidcPasswordProvider';
import { refreshThenLogin } from '../../../renewal';
import {
  cases,
  caseTitle,
  contains,
  matchText,
  notContains,
} from '../../helpers/expectations';
import { wordsOf } from '../../helpers/minted';
import { PACKAGE_ROOT } from '../../helpers/packagePaths';
import { recordingTargets } from '../../helpers/targets';
import { approveDevice } from './formLogin';

const KEYCLOAK_HTTPS_URL = process.env.KEYCLOAK_HTTPS_URL?.replace(/\/+$/, '');
const UAA_URL = process.env.UAA_URL?.replace(/\/+$/, '');
const describeKeycloak = KEYCLOAK_HTTPS_URL ? describe : describe.skip;
const describeUaa = UAA_URL ? describe : describe.skip;
const unlessSet = (name: string, value: string | undefined): string =>
  value ? '' : ` — skipped: ${name} is not set (npm run test:stand sets it)`;

const TLS = join(PACKAGE_ROOT, 'tests/stand/keycloak/tls');
const fixture = (name: string): Buffer => readFileSync(join(TLS, name));
const CLIENT_A: ICertificateMaterial = {
  cert: fixture('client-a.crt'),
  key: fixture('client-a.key'),
};
const CLIENT_B: ICertificateMaterial = {
  cert: fixture('client-b.crt'),
  key: fixture('client-b.key'),
};
const JWT_KEY = fixture('jwt.key');

/** RFC 8705 `x5t#S256`: SHA-256 over the leaf certificate's DER, base64url. */
const thumbprint = (material: ICertificateMaterial): string =>
  createHash('sha256')
    .update(new X509Certificate(material.cert as Buffer).raw)
    .digest('base64url');

const USER = { username: 'tester', password: 'tester' };

const claims = (jwt: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString('utf8'));
const boundTo = (jwt: string): unknown =>
  (claims(jwt).cnf as Record<string, unknown> | undefined)?.['x5t#S256'];

/** Unsigned, never sent: only its `exp` is read, to force a refresh. */
const expiredJwt = (): string => {
  const encode = (value: object) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none' })}.${encode({ exp: Math.floor(Date.now() / 1000) - 3600 })}.sig`;
};

const silentLogger = (onInfo?: (message: string) => void): ILogger => ({
  info: (message: string) => onInfo?.(message),
  error: () => {},
  warn: () => {},
  debug: () => {},
});

interface Answer {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

/**
 * One HTTPS request through Node's own client, presenting exactly `material`
 * (or nothing) in the handshake — the way a consumer's wire presents what a
 * provider's establish() handed its logon target. A fresh agent per request:
 * no TLS session is resumed from another certificate's request.
 */
function send(
  url: string,
  options: {
    material?: ICertificateMaterial | undefined;
    headers?: Record<string, string>;
    form?: Record<string, string>;
  } = {},
): Promise<Answer> {
  const { cert, key, pfx, passphrase } = options.material ?? {};
  const agent = new Agent({ cert, key, pfx, passphrase, keepAlive: false });
  const body = options.form
    ? new URLSearchParams(options.form).toString()
    : undefined;
  return new Promise((resolve, reject) => {
    const req = request(
      url,
      {
        method: body === undefined ? 'GET' : 'POST',
        agent,
        headers: {
          ...options.headers,
          ...(body === undefined
            ? {}
            : { 'Content-Type': 'application/x-www-form-urlencoded' }),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          agent.destroy();
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.on('error', (error) => {
      agent.destroy();
      reject(error);
    });
    req.end(body);
  });
}

describeKeycloak(
  `Client certificates against Keycloak over HTTPS${unlessSet('KEYCLOAK_HTTPS_URL', KEYCLOAK_HTTPS_URL)}`,
  () => {
    const issuer = KEYCLOAK_HTTPS_URL as string;
    let tokenEndpoint = '';
    let userinfoEndpoint = '';
    let deviceEndpoint = '';

    before(async () => {
      const discovery = (await (
        await fetch(`${issuer}/.well-known/openid-configuration`)
      ).json()) as Record<string, string>;
      tokenEndpoint = discovery.token_endpoint!;
      userinfoEndpoint = discovery.userinfo_endpoint!;
      deviceEndpoint = discovery.device_authorization_endpoint!;
    });

    it('the stand’s two client certificates differ, so a thumbprint names one', () => {
      assert.notEqual(thumbprint(CLIENT_A), thumbprint(CLIENT_B));
    });

    describe('tls_client_auth (client `mtls`, subject CN=client-a,O=stand)', () => {
      it('ClientCredentialsProvider gets a token bound to client-a’s certificate', async () => {
        // The endpoint is named, as a consumer names XSUAA's certurl: the
        // provider's uaaUrl would build UAA's path, which Keycloak does not serve.
        const tokens = await new ClientCredentialsProvider({
          renewal: refreshThenLogin(),
          uaaUrl: issuer,
          clientId: 'mtls',
          clientAuthentication: tlsClientCertificate({
            material: CLIENT_A,
            endpoint: tokenEndpoint,
          }),
        }).getTokens();

        const token = claims(tokens.authorizationToken);
        assert.equal(token.iss, issuer);
        assert.equal(token.azp, 'mtls');
        assert.equal(boundTo(tokens.authorizationToken), thumbprint(CLIENT_A));
      });

      it('a token request presenting client-b is refused, in the fixed words', async () => {
        const provider = new ClientCredentialsProvider({
          renewal: refreshThenLogin(),
          uaaUrl: issuer,
          clientId: 'mtls',
          clientAuthentication: tlsClientCertificate({
            material: CLIENT_B,
            endpoint: tokenEndpoint,
          }),
        });

        // Keycloak itself refused the client — not the handshake, not trust.
        // Its answer does not tell client-b from no certificate at all:
        // measured 2026-10-04, both are 401 invalid_client "Invalid client or
        // Invalid client credentials". What makes this client-b's refusal is
        // the case above: the same configuration with client-a gets a token.
        // Since 5.4.2 the message names the status and the registered code
        // only — Keycloak's description is written nowhere.
        const thrown = await provider.getTokens().then(
          () => undefined,
          (error: unknown) => error as Error,
        );
        // The status and the registered code are the failure's facts.
        matchText(thrown?.message, /\(HTTP 401, invalid_client\)$/);
        notContains(
          inspect(thrown, { depth: null }),
          'Invalid client or Invalid client credentials',
        );
        // The client credentials request's own words.
        assert.deepEqual(wordsOf(await provider.prepare()), {
          ok: false,
          refusal: {
            reason:
              'the client credentials request failed (HTTP 401, invalid_client)',
          },
        });
      });

      describe('the bound token at a resource (userinfo)', () => {
        let token = '';
        let presented: ICertificateMaterial | undefined;
        let authorization = '';

        before(async () => {
          // A user token with `openid`: userinfo answers 403 to a token
          // without that scope before it looks at the binding.
          const provider = new OidcPasswordProvider({
            renewal: refreshThenLogin(),
            issuerUrl: issuer,
            clientId: 'mtls',
            ...USER,
            scopes: ['openid'],
            clientAuthentication: tlsClientCertificate({ material: CLIENT_A }),
          });
          token = (await provider.getTokens()).authorizationToken;

          const targets = recordingTargets();
          assert.deepEqual(await provider.establish(targets.logonTarget), {
            ok: true,
          });
          assert.deepEqual(await provider.authorize(targets.requestTarget), {
            ok: true,
          });
          [presented] = targets.logon.tls;
          authorization = targets.request.headers.Authorization!;
        });

        it('establish() hands the logon client-a’s certificate, the one the token is bound to', () => {
          assert.equal(boundTo(token), thumbprint(CLIENT_A));
          assert.notEqual(presented, undefined);
          assert.equal(
            thumbprint(presented as ICertificateMaterial),
            thumbprint(CLIENT_A),
          );
          assert.equal(authorization, `Bearer ${token}`);
        });

        it('with that certificate userinfo answers 200 for the token’s user', async () => {
          const answer = await send(userinfoEndpoint, {
            material: presented,
            headers: { Authorization: authorization },
          });

          assert.equal(answer.status, 200);
          assert.equal(JSON.parse(answer.body).preferred_username, 'tester');
        });

        for (const [caseIndex, caseRow] of cases([
          ['no certificate', undefined],
          ['client-b', CLIENT_B],
        ]).entries()) {
          const [_label, material] = caseRow;
          it(
            caseTitle(
              'with %s userinfo refuses the same token as not bound to it',
              caseRow,
              caseIndex,
            ),
            async () => {
              const answer = await send(userinfoEndpoint, {
                material,
                headers: { Authorization: authorization },
              });

              assert.equal(answer.status, 401);
              contains(
                answer.headers['www-authenticate'],
                'Client certificate missing, or its thumbprint and one in the token did NOT match',
              );
            },
          );
        }
      });

      it('OidcPasswordProvider refreshes over mTLS, and the new token is bound to the same certificate', async () => {
        const first = await new OidcPasswordProvider({
          renewal: refreshThenLogin(),
          issuerUrl: issuer,
          clientId: 'mtls',
          ...USER,
          scopes: ['openid'],
          clientAuthentication: tlsClientCertificate({ material: CLIENT_A }),
        }).getTokens();
        assert.equal(boundTo(first.authorizationToken), thumbprint(CLIENT_A));

        // A wrong password: a fall back to the password grant would fail, so
        // only a refresh can produce a token here.
        const refreshed = await new OidcPasswordProvider({
          renewal: refreshThenLogin(),
          issuerUrl: issuer,
          clientId: 'mtls',
          username: 'tester',
          password: 'not-the-password',
          scopes: ['openid'],
          accessToken: expiredJwt(),
          refreshToken: first.refreshToken,
          clientAuthentication: tlsClientCertificate({ material: CLIENT_A }),
        }).getTokens();

        assert.notEqual(
          claims(refreshed.authorizationToken).jti,
          claims(first.authorizationToken).jti,
        );
        assert.equal(claims(refreshed.authorizationToken).azp, 'mtls');
        assert.equal(
          boundTo(refreshed.authorizationToken),
          thumbprint(CLIENT_A),
        );
      });
    });

    describe('private_key_jwt (client `jwt`, the stand’s signing key)', () => {
      it('OidcPasswordProvider gets a token with the default audience, the token endpoint', async () => {
        const tokens = await new OidcPasswordProvider({
          renewal: refreshThenLogin(),
          issuerUrl: issuer,
          clientId: 'jwt',
          ...USER,
          scopes: ['openid'],
          clientAuthentication: privateKeyJwt({
            key: JWT_KEY,
            algorithm: 'RS256',
          }),
        }).getTokens();

        const token = claims(tokens.authorizationToken);
        assert.equal(token.azp, 'jwt');
        assert.equal(token.preferred_username, 'tester');
        assert.equal(token.cnf, undefined);
      });

      // Measured 2026-10-04 on Keycloak 26.7.4: the device authorization
      // endpoint is not an audience Keycloak accepts for a client assertion.
      // This is why the default audience is the draft's tokenEndpoint (5.3.0),
      // not the endpoint the request goes to; `audience` still overrides it.
      it('Keycloak refuses an assertion whose audience is the device endpoint', async () => {
        assert.match(deviceEndpoint, /^https:/);
        const provider = OidcDeviceFlowProvider.toConsole({
          renewal: refreshThenLogin(),
          issuerUrl: issuer,
          clientId: 'jwt',
          scopes: ['openid'],
          logger: silentLogger(),
          clientAuthentication: privateKeyJwt({
            key: JWT_KEY,
            algorithm: 'RS256',
            audience: deviceEndpoint,
          }),
        });

        // The refusal is the client's (400 invalid_client), and only the
        // audience differs from the next case, which completes. Keycloak's
        // description ("Invalid token audience") is written nowhere.
        const thrown = await provider.getTokens().then(
          () => undefined,
          (error: unknown) => error as Error,
        );
        assert.equal(
          thrown?.message,
          'the OIDC device authorization failed (HTTP 400, invalid_client)',
        );
        notContains(inspect(thrown, { depth: null }), 'Invalid token audience');
      });

      it('the device flow completes with the default audience — the token endpoint, no `audience` given', async () => {
        let approval: Promise<void> | undefined;
        const logger = silentLogger((message) => {
          const complete = /^Or use: (\S+)/.exec(message)?.[1];
          if (complete && !approval) {
            approval = approveDevice(complete, USER);
          }
        });

        const tokens = await OidcDeviceFlowProvider.toConsole({
          renewal: refreshThenLogin(),
          issuerUrl: issuer,
          clientId: 'jwt',
          scopes: ['openid'],
          logger,
          clientAuthentication: privateKeyJwt({
            key: JWT_KEY,
            algorithm: 'RS256',
          }),
        }).getTokens();

        await approval;
        assert.notEqual(approval, undefined);
        assert.equal(claims(tokens.authorizationToken).azp, 'jwt');
        assert.equal(
          claims(tokens.authorizationToken).preferred_username,
          'tester',
        );
      });
    });

    describe('X.509 user logon — the CERTRULE analogue (client `x509-login`)', () => {
      /**
       * A direct grant through the realm's X.509 flow: the user is the one the
       * presented certificate's CN names. No username, no password.
       */
      const logon = (material: ICertificateMaterial | undefined) =>
        send(tokenEndpoint, {
          material,
          form: { grant_type: 'password', client_id: 'x509-login' },
        });

      it('client-a, as CertificateAuthProvider presents it, logs on as the user client-a', async () => {
        const provider = CertificateAuthProvider.fromFiles({
          url: issuer,
          authType: 'certificate',
          certPath: join(TLS, 'client-a.crt'),
          certKeyPath: join(TLS, 'client-a.key'),
        });
        assert.deepEqual(await provider.prepare(), { ok: true });
        const targets = recordingTargets();
        assert.deepEqual(await provider.establish(targets.logonTarget), {
          ok: true,
        });
        assert.equal(targets.logon.tls.length, 1);

        const answer = await logon(targets.logon.tls[0]);

        assert.equal(answer.status, 200);
        const token = claims(JSON.parse(answer.body).access_token);
        assert.equal(token.azp, 'x509-login');
        assert.equal(token.preferred_username, 'client-a');
      });

      it('client-b, mapped to no user, is refused', async () => {
        const provider = CertificateAuthProvider.fromFiles({
          url: issuer,
          authType: 'certificate',
          certPath: join(TLS, 'client-b.crt'),
          certKeyPath: join(TLS, 'client-b.key'),
        });
        assert.deepEqual(await provider.prepare(), { ok: true });
        const targets = recordingTargets();
        assert.deepEqual(await provider.establish(targets.logonTarget), {
          ok: true,
        });

        const answer = await logon(targets.logon.tls[0]);

        assert.equal(answer.status, 400);
        assert.deepEqual(JSON.parse(answer.body), {
          error: 'invalid_grant',
          error_description: 'Invalid user credentials',
        });
      });

      it('no certificate is refused as missing', async () => {
        const answer = await logon(undefined);

        assert.equal(answer.status, 401);
        assert.deepEqual(JSON.parse(answer.body), {
          error: 'invalid_request',
          error_description: 'X509 client certificate is missing.',
        });
      });
    });
  },
);

describeUaa(
  `private_key_jwt against Cloud Foundry UAA${unlessSet('UAA_URL', UAA_URL)}`,
  () => {
    /**
     * The audience UAA accepts is its issuer, `…/uaa/oauth/token` — taken from
     * its discovery, not from UAA_URL, which may use another port than the
     * committed configuration names.
     */
    let uaaIssuer = '';
    before(async () => {
      const discovery = await fetch(
        `${UAA_URL}/.well-known/openid-configuration`,
      );
      uaaIssuer = ((await discovery.json()) as { issuer: string }).issuer;
    });

    it('ClientCredentialsProvider gets a client token with no secret', async () => {
      const tokens = await new ClientCredentialsProvider({
        renewal: refreshThenLogin(),
        uaaUrl: UAA_URL as string,
        clientId: 'jwt_client',
        clientAuthentication: privateKeyJwt({
          key: JWT_KEY,
          algorithm: 'RS256',
          audience: uaaIssuer,
        }),
      }).getTokens();

      const token = claims(tokens.authorizationToken);
      assert.equal(token.iss, uaaIssuer);
      assert.equal(token.grant_type, 'client_credentials');
      assert.equal(token.client_id, 'jwt_client');
    });
  },
);
