import { describe, expect, it } from '@jest/globals';
import { generateKeyMaterial } from '@mcp-abap-adt/auth-mocks';
import { AuthorizationCodeProvider } from '../../providers/AuthorizationCodeProvider';
import { OidcBrowserProvider } from '../../providers/OidcBrowserProvider';
import { Saml2BearerProvider } from '../../providers/Saml2BearerProvider';
import { Saml2PureProvider } from '../../providers/Saml2PureProvider';
import { UaaPasscodeProvider } from '../../providers/UaaPasscodeProvider';
import { BrowserCallbackStrategy } from '../../strategies/BrowserCallbackStrategy';
import { isShippedValidator } from '../../validation/assertionValidator';

const configOf = (p: unknown) =>
  (p as { config: Record<string, unknown> }).config;
const uaa = { uaaUrl: 'https://uaa', clientId: 'c', clientSecret: 's' };
const saml = {
  idpSsoUrl: 'https://idp/sso',
  spEntityId: 'sp',
  idpEntityId: 'idp',
  cookieProvider: async () => 'c=1',
};
// Not the brief's literal 'MIIB': that is too short to be a parseable X.509
// certificate, and `toPem` proves the certificate before anything uses it
// (src/validation/signedNode.ts), so a placeholder that short throws at
// construction rather than reaching the assertion under test.
const CERT = generateKeyMaterial().certificatePem;

describe('no implicit defaults', () => {
  it('constructors require the collaborator (compile-time)', () => {
    // @ts-expect-error authorization is required
    expect(() => new AuthorizationCodeProvider({ ...uaa })).toBeDefined();
    // @ts-expect-error authorization is required
    expect(() => new OidcBrowserProvider({ clientId: 'c' })).toBeDefined();
    const uaaPasscode = () =>
      // @ts-expect-error authorization is required
      new UaaPasscodeProvider({ uaaUrl: 'https://uaa', clientId: 'c' });
    expect(uaaPasscode).toBeDefined();
    // @ts-expect-error authorization and assertionValidator are required
    expect(() => new Saml2PureProvider({ ...saml })).toBeDefined();
  });

  it('inBrowser assembles a browser callback strategy', () => {
    expect(
      configOf(AuthorizationCodeProvider.inBrowser(uaa)).authorization,
    ).toBeInstanceOf(BrowserCallbackStrategy);
    expect(
      configOf(OidcBrowserProvider.inBrowser({ clientId: 'c' })).authorization,
    ).toBeInstanceOf(BrowserCallbackStrategy);
  });

  it('fromTerminal assembles a manual strategy with dispose()', () => {
    const strategy = configOf(
      UaaPasscodeProvider.fromTerminal({
        uaaUrl: 'https://uaa',
        clientId: 'c',
      }),
    ).authorization as { dispose?: unknown };
    expect(typeof strategy.dispose).toBe('function');
  });

  it('the SAML recipes assemble a callback strategy and a shipped validator', () => {
    for (const p of [
      Saml2PureProvider.inBrowser(saml, { idpCertificates: [CERT] }),
      Saml2BearerProvider.inBrowser(
        {
          ...saml,
          tokenUrl: 'https://uaa/oauth/token',
          clientId: 'c',
          clientSecret: 's',
        },
        { idpCertificates: [CERT] },
      ),
    ]) {
      expect(configOf(p).authorization).toBeInstanceOf(BrowserCallbackStrategy);
      expect(isShippedValidator(configOf(p).assertionValidator as never)).toBe(
        true,
      );
    }
  });
});
