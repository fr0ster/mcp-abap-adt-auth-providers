/**
 * The package's public surface for SAML assertion validation: what a consumer
 * may import from the package root, and what stays implementation.
 */

import { describe, expect, it } from '@jest/globals';
import type { AssertionCheck } from '@mcp-abap-adt/interfaces-auth';
import type { ShippedValidatorOptions } from '../index';
import * as surface from '../index';

describe('public exports — SAML assertion validation', () => {
  it.each([
    'createSignedResponseValidator',
    'createSignedAssertionValidator',
    'createInMemoryReplayStore',
    'defaultReplayStore',
  ])('exports %s', (name) => {
    expect((surface as Record<string, unknown>)[name]).toBeDefined();
  });

  it("exports the type ShippedValidatorOptions; AssertionCheck is interfaces-auth's", () => {
    // Type-only exports vanish at runtime; this compiles only while they are
    // exported, since ts-jest type-checks the suite before running it.
    // AssertionCheck moved to interfaces-auth (6.0.0).
    const check: AssertionCheck = 'replay';
    const options: ShippedValidatorOptions = {
      idpCertificates: [],
      replayStore: surface.defaultReplayStore,
    };
    expect(check).toBe('replay');
    expect(options.idpCertificates).toEqual([]);
  });

  it.each([
    'parseXsdDateTime',
    'findDuplicateId',
    'resolveSignedElements',
    'isShippedValidator',
  ])('does not export the internal %s', (name) => {
    expect(name in surface).toBe(false);
  });

  it('no longer exports parseSamlNotOnOrAfter', () => {
    expect('parseSamlNotOnOrAfter' in surface).toBe(false);
  });
});

describe('public exports — 5.0.0', () => {
  it.each([
    'BasicAuthProvider',
    'CertificateAuthProvider',
    'FileCertificateMaterialLoader',
    'SamlAuthProvider',
    'TokenAuthProvider',
    'SncLogonProvider',
    'DefaultSncLibraryLocator',
    'SecureLoginClientProbe',
    'nodeSncSystem',
    'consoleDeviceCodePresenter',
    'AuthProviderBase',
  ])('exports %s', (name) => {
    expect((surface as Record<string, unknown>)[name]).toBeDefined();
  });
  it.each([
    'libraryArchitectures',
    'sncRefusal',
    'refusalFrom',
    'oops',
    'safely',
    'ownLabel',
    'DeviceCodePresentationError',
    'KNOWN_CONFIG_FIELDS',
    'KNOWN_RFC_KEYS',
    'parseRegQuery',
    'SncLibraryNotFoundError',
  ])('does not export the internal %s', (name) => {
    expect(name in surface).toBe(false);
  });
});

// The error classes, refusalWords
// and every transition piece are gone from the surface — a consumer reads a
// failure with auth-errors' readFailure and switches on its kind.
describe('public exports — 6.0.0 removals', () => {
  it.each([
    'refusalWords',
    'AssertionValidationError',
    'CertificateMaterialError',
    'BasicClientIdError',
    'ClientAuthenticationError',
    'ClientAuthenticationResultError',
    'TokenEndpointError',
    'BrowserAuthError',
    'RefreshError',
    'ServiceKeyError',
    'SessionDataError',
    'TokenProviderError',
    'ValidationError',
    'CallbackScopeError',
    'AuthorizationRefusedError',
    'DEFAULT_LOGIN_TIMEOUT_MS',
    'legacyBasic',
    'rejectMissingToken',
    'asContract',
    'toLegacyOutcome',
    'toLegacyRefusal',
    'loggedError',
  ])('does not export %s', (name) => {
    expect(name in surface).toBe(false);
  });
});

describe('public exports — renewal strategies', () => {
  it.each(['refreshThenLogin', 'refreshOnly'])('exports %s', (name) => {
    expect(typeof (surface as Record<string, unknown>)[name]).toBe('function');
  });

  it.each(['readDecision', 'needsSentDecision'])(
    'does not export the internal %s',
    (name) => {
      expect(name in surface).toBe(false);
    },
  );
});

describe('public exports — the persistence strategy', () => {
  it('exports refreshStatePersistence', () => {
    expect(
      typeof (surface as Record<string, unknown>).refreshStatePersistence,
    ).toBe('function');
  });
});

// The composer and its parts are public; the 5.x
// class, its callback server factories and their scope are gone.
describe('public exports — no universal browser', () => {
  it.each(['systemBrowser', 'chromeBrowser', 'edgeBrowser', 'firefoxBrowser'])(
    '%s is not exported: the consumer picks the browser for its platform',
    (name) => {
      expect(name in (surface as Record<string, unknown>)).toBe(false);
    },
  );
});

describe('public exports — authorization by composition', () => {
  it.each([
    'composeAuthorization',
    'openInBrowser',
    'linuxDefaultBrowser',
    'linuxBrowser',
    'macDefaultBrowser',
    'macBrowser',
    'windowsDefaultBrowser',
    'windowsBrowser',
    'showUrl',
    'consumerPresentation',
    'loopback',
    'loopback4',
    'loopback6',
    'terminalPaste',
    'consumerAnswer',
    'consumerHandoff',
    'oauthCode',
    'oidcCode',
    'samlResponse',
    'passcode',
    'readFromTerminal',
    'browserCallbackStrategy',
    'oidcCallbackStrategy',
    'samlCallbackStrategy',
    'manualPasteStrategy',
    'manualSamlResponseStrategy',
    'manualPasscodeStrategy',
    'externalCodeStrategy',
    'staticCodeStrategy',
    'asOidcResult',
  ])('exports %s', (name) => {
    expect(typeof (surface as Record<string, unknown>)[name]).toBe('function');
  });

  it('exports DEFAULT_CALLBACK_PORT, 61001', () => {
    expect(surface.DEFAULT_CALLBACK_PORT).toBe(61001);
  });

  it.each([
    'BrowserCallbackStrategy',
    'withBrowserCallbackServer',
    'withOidcCallbackServer',
    'withSamlCallbackServer',
    'runCallbackScope',
    'httpListener',
    'openHttpListener',
  ])('does not export %s', (name) => {
    expect(name in surface).toBe(false);
  });
});
