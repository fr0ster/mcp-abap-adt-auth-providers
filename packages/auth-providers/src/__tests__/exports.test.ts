/**
 * The package's public surface for SAML assertion validation: what a consumer
 * may import from the package root, and what stays implementation.
 */

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { AssertionCheck } from '@mcp-abap-adt/interfaces-auth';
import type { ShippedValidatorOptions } from '../index';
import * as surface from '../index';
import { caseTitle } from './helpers/expectations';

describe('public exports — SAML assertion validation', () => {
  for (const [caseIndex, caseRow] of [
    'createSignedResponseValidator',
    'createSignedAssertionValidator',
    'createInMemoryReplayStore',
    'defaultReplayStore',
  ].entries()) {
    const name = caseRow;
    it(caseTitle('exports %s', caseRow, caseIndex), () => {
      assert.notEqual((surface as Record<string, unknown>)[name], undefined);
    });
  }

  it("exports the type ShippedValidatorOptions; AssertionCheck is interfaces-auth's", () => {
    // Type-only exports vanish at runtime; this compiles only while they are
    // exported, since ts-jest type-checks the suite before running it.
    // AssertionCheck moved to interfaces-auth (6.0.0).
    const check: AssertionCheck = 'replay';
    const options: ShippedValidatorOptions = {
      idpCertificates: [],
      replayStore: surface.defaultReplayStore,
    };
    assert.equal(check, 'replay');
    assert.deepEqual(options.idpCertificates, []);
  });

  for (const [caseIndex, caseRow] of [
    'parseXsdDateTime',
    'findDuplicateId',
    'resolveSignedElements',
    'isShippedValidator',
  ].entries()) {
    const name = caseRow;
    it(caseTitle('does not export the internal %s', caseRow, caseIndex), () => {
      assert.equal(name in surface, false);
    });
  }

  it('no longer exports parseSamlNotOnOrAfter', () => {
    assert.equal('parseSamlNotOnOrAfter' in surface, false);
  });
});

describe('public exports — 5.0.0', () => {
  for (const [caseIndex, caseRow] of [
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
  ].entries()) {
    const name = caseRow;
    it(caseTitle('exports %s', caseRow, caseIndex), () => {
      assert.notEqual((surface as Record<string, unknown>)[name], undefined);
    });
  }
  for (const [caseIndex, caseRow] of [
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
  ].entries()) {
    const name = caseRow;
    it(caseTitle('does not export the internal %s', caseRow, caseIndex), () => {
      assert.equal(name in surface, false);
    });
  }
});

// The error classes, refusalWords
// and every transition piece are gone from the surface — a consumer reads a
// failure with auth-errors' readFailure and switches on its kind.
describe('public exports — 6.0.0 removals', () => {
  for (const [caseIndex, caseRow] of [
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
  ].entries()) {
    const name = caseRow;
    it(caseTitle('does not export %s', caseRow, caseIndex), () => {
      assert.equal(name in surface, false);
    });
  }
});

describe('public exports — renewal strategies', () => {
  for (const [caseIndex, caseRow] of [
    'refreshThenLogin',
    'refreshOnly',
  ].entries()) {
    const name = caseRow;
    it(caseTitle('exports %s', caseRow, caseIndex), () => {
      assert.equal(
        typeof (surface as Record<string, unknown>)[name],
        'function',
      );
    });
  }

  for (const [caseIndex, caseRow] of [
    'readDecision',
    'checkDecision',
    'needsSentDecision',
  ].entries()) {
    const name = caseRow;
    it(caseTitle('does not export the internal %s', caseRow, caseIndex), () => {
      assert.equal(name in surface, false);
    });
  }
});

describe('public exports — the persistence strategy', () => {
  it('exports refreshStatePersistence', () => {
    assert.equal(
      typeof (surface as Record<string, unknown>).refreshStatePersistence,
      'function',
    );
  });
});

// The composer and its parts are public; the 5.x
// class, its callback server factories and their scope are gone.
describe('public exports — no universal browser', () => {
  for (const [caseIndex, caseRow] of [
    'systemBrowser',
    'chromeBrowser',
    'edgeBrowser',
    'firefoxBrowser',
  ].entries()) {
    const name = caseRow;
    it(
      caseTitle(
        '%s is not exported: the consumer picks the browser for its platform',
        caseRow,
        caseIndex,
      ),
      () => {
        assert.equal(name in (surface as Record<string, unknown>), false);
      },
    );
  }
});

describe('public exports — authorization by composition', () => {
  for (const [caseIndex, caseRow] of [
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
  ].entries()) {
    const name = caseRow;
    it(caseTitle('exports %s', caseRow, caseIndex), () => {
      assert.equal(
        typeof (surface as Record<string, unknown>)[name],
        'function',
      );
    });
  }

  it('exports DEFAULT_CALLBACK_PORT, 61001', () => {
    assert.equal(surface.DEFAULT_CALLBACK_PORT, 61001);
  });

  for (const [caseIndex, caseRow] of [
    'BrowserCallbackStrategy',
    'withBrowserCallbackServer',
    'withOidcCallbackServer',
    'withSamlCallbackServer',
    'runCallbackScope',
    'httpListener',
    'openHttpListener',
  ].entries()) {
    const name = caseRow;
    it(caseTitle('does not export %s', caseRow, caseIndex), () => {
      assert.equal(name in surface, false);
    });
  }
});
