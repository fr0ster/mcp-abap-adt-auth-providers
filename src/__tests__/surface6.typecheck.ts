/**
 * Type test, compiled by `test:check` and run by nothing: the
 * package root exports none of the names 6.0.0 deletes — the error classes,
 * `refusalWords` (`classify` from auth-errors), the
 * transition pieces, the internals of the token sites, and
 * `DEFAULT_LOGIN_TIMEOUT_MS`. A consumer reads a failure with
 * `readFailure` and switches on `kind`.
 *
 * Each name is read off the module's type, one line per name, rather than
 * through `import { … }` lines: Biome's import sorting merges imports from one
 * module, which would move the names away from their `@ts-expect-error`.
 */

type Surface = typeof import('../index');

// @ts-expect-error refusalWords is gone: classify(error, operation)
export type V01 = Surface['refusalWords'];

// @ts-expect-error the class is gone: kind 'saml-assertion'
export type V02 = Surface['AssertionValidationError'];

// @ts-expect-error the class is gone: kind 'client-certificate'
export type V03 = Surface['CertificateMaterialError'];

// @ts-expect-error the class is gone: kind 'client-authentication'
export type V04 = Surface['BasicClientIdError'];

// @ts-expect-error the class is gone: kind 'client-authentication'
export type V05 = Surface['ClientAuthenticationError'];

// @ts-expect-error the class is gone: kind 'client-authentication'
export type V06 = Surface['ClientAuthenticationResultError'];

// @ts-expect-error the class is gone: kind 'request-failed'
export type V07 = Surface['TokenEndpointError'];

// @ts-expect-error the class is gone: kind 'interactive-login'
export type V08 = Surface['BrowserAuthError'];

// @ts-expect-error the class is gone: kind 'credential-refused'
export type V09 = Surface['RefreshError'];

// @ts-expect-error the class is gone, without a replacement (no producer)
export type V10 = Surface['ServiceKeyError'];

// @ts-expect-error the class is gone, without a replacement (no producer)
export type V11 = Surface['SessionDataError'];

// @ts-expect-error the class is gone: AuthProviderFailure
export type V12 = Surface['TokenProviderError'];

// @ts-expect-error the class is gone: kind 'configuration'
export type V13 = Surface['ValidationError'];

// @ts-expect-error the internal class is gone: kind 'interactive-login'
export type V14 = Surface['DeviceCodePresentationError'];

// @ts-expect-error the internal class is gone: kind 'interactive-login'
export type V15 = Surface['CallbackScopeError'];

// @ts-expect-error the internal class is gone: kind 'interactive-login'
export type V16 = Surface['AuthorizationRefusedError'];

// @ts-expect-error the built-in login bound is gone
export type V17 = Surface['DEFAULT_LOGIN_TIMEOUT_MS'];

// @ts-expect-error internal: the one legacy Basic header builder
export type V18 = Surface['legacyBasic'];

// @ts-expect-error internal: an answer without a token
export type V19 = Surface['rejectMissingToken'];

// @ts-expect-error the transition bridge is gone
export type V20 = Surface['asContract'];

// @ts-expect-error the transition bridge is gone
export type V21 = Surface['toLegacyOutcome'];

// @ts-expect-error the transition bridge is gone
export type V22 = Surface['toLegacyRefusal'];

// @ts-expect-error gone: logFields(classify(error, operation))
export type V23 = Surface['loggedError'];

// @ts-expect-error gone: classify(error, operation)
export type V24 = Surface['refusalFrom'];

// @ts-expect-error AssertionCheck comes from interfaces-auth
export type T01 = import('../index').AssertionCheck;

// @ts-expect-error interfaces-auth 6.0.0's AuthorizationRequest carries signal
export type T02 = import('../index').SignalledAuthorizationRequest;

// @ts-expect-error interfaces-auth 6.0.0's ITokenRequestOptions instead
export type T03 = import('../index').TokenRequestOptions;

// @ts-expect-error interfaces-auth 6.0.0's ITokenResult carries the disposition
export type T04 = import('../index').TokenResultWithDisposition;

// @ts-expect-error internal: a token site's own description
export type T05 = import('../index').TokenRequestSite;

// Positive lines: what stays exported reads the same way.
export type Kept = Surface['AuthProviderBase'] | Surface['BaseTokenProvider'];
export type KeptType = import('../index').TokenProviderHooks;
