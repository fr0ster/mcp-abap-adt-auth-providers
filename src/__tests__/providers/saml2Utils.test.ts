/**
 * The AuthnRequest ID surviving from URL building to `getSamlAssertion`.
 *
 * `buildSamlAuthorizationUrl` is exercised here rather than in its own file
 * because the rule this task adds — where the expected request ID comes from —
 * spans both functions: the ID `buildSamlAuthorizationUrl` mints is exactly
 * what `getSamlAssertion` must thread through, or refuse to proceed without.
 */

import { describe, expect, it } from '@jest/globals';
import type {
  AuthorizationOutcome,
  AuthorizationRequest,
  IAuthorizationStrategy,
} from '@mcp-abap-adt/interfaces-auth';
import { buildSamlAuthorizationUrl } from '../../auth/saml2Auth';
import { ValidationError } from '../../errors/TokenProviderErrors';
import {
  getSamlAssertion,
  type Saml2CommonConfig,
} from '../../providers/saml2Utils';

describe('buildSamlAuthorizationUrl', () => {
  it('mints a request ID and reports it', () => {
    const built = buildSamlAuthorizationUrl({
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'urn:sp',
      acsUrl: 'http://localhost:61001/acs',
    });
    expect(built.requestId).toMatch(/^_/);
    expect(built.url).toContain('SAMLRequest=');
  });

  it('puts the ID it reports into the request it builds', () => {
    const built = buildSamlAuthorizationUrl({
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'urn:sp',
      acsUrl: 'http://localhost:61001/acs',
    });
    const encoded = new URL(built.url).searchParams.get('SAMLRequest') ?? '';
    const xml = require('node:zlib')
      .inflateRawSync(Buffer.from(encoded, 'base64'))
      .toString('utf8');
    expect(xml).toContain(`ID="${built.requestId}"`);
  });

  it('mints nothing for a pre-built authorization URL', () => {
    const built = buildSamlAuthorizationUrl({
      idpSsoUrl: 'https://idp.example/sso',
      spEntityId: 'urn:sp',
      acsUrl: 'http://localhost:61001/acs',
      authorizationUrl: 'https://idp.example/preauthorized?SAMLRequest=xyz',
    });
    expect(built.url).toBe('https://idp.example/preauthorized?SAMLRequest=xyz');
    expect(built.requestId).toBeUndefined();
  });
});

describe('getSamlAssertion — where the expected request ID comes from', () => {
  const baseConfig = {
    idpSsoUrl: 'https://idp.example/sso',
    spEntityId: 'urn:sp',
  };

  /** Calls the builder — the strategy that asks for a URL, as a real browser flow does. */
  function callsBuilder(
    redirectUri: string,
    payload = 'PHNhbWw+',
  ): IAuthorizationStrategy<string> {
    return {
      async authorize(
        request: AuthorizationRequest,
      ): Promise<AuthorizationOutcome<string>> {
        await request.buildAuthorizationUrl(redirectUri);
        return { payload, redirectUri };
      },
    };
  }

  /** Never calls the builder — a strategy that already holds the payload. */
  function neverCallsBuilder(
    redirectUri: string,
    payload = 'PHNhbWw+',
  ): IAuthorizationStrategy<string> {
    return {
      async authorize(): Promise<AuthorizationOutcome<string>> {
        return { payload, redirectUri };
      },
    };
  }

  it('reports the ID it minted while building the request', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      authorization: callsBuilder('http://localhost:61001/callback'),
    };

    const result = await getSamlAssertion(config);

    expect(result.requestId).toMatch(/^_/);
    expect(result.payload).toBe('PHNhbWw+');
  });

  it('reports outcome.redirectUri as acsUrl, not config.acsUrl', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      authorization: callsBuilder('http://localhost:61001/callback'),
    };

    const result = await getSamlAssertion(config);

    expect(result.acsUrl).toBe('http://localhost:61001/callback');
  });

  it('uses the declared authnRequestId when the builder was never called', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      authnRequestId: '_declared-id',
      authorization: neverCallsBuilder('http://localhost:61001/callback'),
    };

    const result = await getSamlAssertion(config);

    expect(result.requestId).toBe('_declared-id');
  });

  it('yields requestId undefined when idpInitiated is declared and the builder was never called', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      idpInitiated: true,
      authorization: neverCallsBuilder('http://localhost:61001/callback'),
    };

    const result = await getSamlAssertion(config);

    expect(result.requestId).toBeUndefined();
  });

  it('throws a ValidationError naming authnRequestId when no ID can be established', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      authorization: neverCallsBuilder('http://localhost:61001/callback'),
    };

    const rejected = expect(getSamlAssertion(config)).rejects.toThrow(
      ValidationError,
    );
    await rejected;
    await expect(getSamlAssertion(config)).rejects.toMatchObject({
      missingFields: ['authnRequestId'],
    });
  });

  it('never infers idpInitiated from a strategy that simply did not call the builder', async () => {
    // Same shape as the previous case, restated: omitting the declaration is
    // not read as "no request was sent" — that must be said explicitly.
    const config: Saml2CommonConfig = {
      ...baseConfig,
      authorization: neverCallsBuilder('http://localhost:61001/callback'),
    };

    await expect(getSamlAssertion(config)).rejects.toThrow(
      /authnRequestId must be configured/,
    );
  });

  it('throws a ValidationError when idpInitiated is combined with a minted ID', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      idpInitiated: true,
      authorization: callsBuilder('http://localhost:61001/callback'),
    };

    await expect(getSamlAssertion(config)).rejects.toThrow(ValidationError);
  });

  it('throws a ValidationError when idpInitiated is combined with a declared authnRequestId', async () => {
    const config: Saml2CommonConfig = {
      ...baseConfig,
      idpInitiated: true,
      authnRequestId: '_declared-id',
      authorization: neverCallsBuilder('http://localhost:61001/callback'),
    };

    await expect(getSamlAssertion(config)).rejects.toThrow(ValidationError);
  });
});
