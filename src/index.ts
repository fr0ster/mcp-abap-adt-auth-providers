/**
 * @mcp-abap-adt/auth-providers
 * Token providers for MCP ABAP ADT auth-broker
 *
 * Provides token providers
 */

// Callback server factories — "take the transport this package gives".
export { withBrowserCallbackServer } from './auth/callbackServer';
export type { OidcCallbackResult } from './auth/oidcBrowserAuth';
export { withOidcCallbackServer } from './auth/oidcBrowserAuth';
export { refusalWords } from './auth/refusal';
export { withSamlCallbackServer } from './auth/saml2Auth';
// How a token provider's client authenticates to the authorization server.
export * from './clientAuthentication';
// Credentials the process delegates to — every one an IAuthProvider.
export { BasicAuthProvider } from './credentials/BasicAuthProvider';
export { CertificateAuthProvider } from './credentials/CertificateAuthProvider';
export { FileCertificateMaterialLoader } from './credentials/FileCertificateMaterialLoader';
export { SamlAuthProvider } from './credentials/SamlAuthProvider';
export { TokenAuthProvider } from './credentials/TokenAuthProvider';
// Device flow: how the user is shown the code — injected like a strategy.
export {
  consoleDeviceCodePresenter,
  type DeviceCodePrompt,
  type IDeviceCodePresenter,
} from './deviceCode/DeviceCodePresenter';
// Errors
export {
  type AssertionCheck,
  AssertionValidationError,
} from './errors/AssertionValidationError';
export { CertificateMaterialError } from './errors/CertificateMaterialError';
export {
  BasicClientIdError,
  ClientAuthenticationError,
  ClientAuthenticationResultError,
} from './errors/ClientAuthenticationError';
export { TokenEndpointError } from './errors/TokenEndpointError';
export {
  BrowserAuthError,
  RefreshError,
  ServiceKeyError,
  SessionDataError,
  TokenProviderError,
  ValidationError,
} from './errors/TokenProviderErrors';
export type {
  AuthorizationCodeProviderConfig,
  ClientCredentialsProviderConfig,
  OidcBrowserProviderConfig,
  OidcDeviceFlowProviderConfig,
  OidcPasswordProviderConfig,
  OidcTokenExchangeProviderConfig,
  Saml2BearerProviderConfig,
  Saml2PureProviderConfig,
  TokenProviderHooks,
  UaaPasscodeProviderConfig,
} from './providers';
// Token Providers (stateful providers with automatic token lifecycle)
export {
  AuthorizationCodeProvider,
  BaseTokenProvider,
  ClientCredentialsProvider,
  OidcBrowserProvider,
  OidcDeviceFlowProvider,
  OidcPasswordProvider,
  OidcTokenExchangeProvider,
  Saml2BearerProvider,
  Saml2PureProvider,
  UaaPasscodeProvider,
} from './providers';
export type { SamlTrust } from './providers/saml2Utils';
// SNC — passwordless RFC logon.
export {
  DefaultSncLibraryLocator,
  type ISncLibraryLocator,
  type SncLibrary,
} from './snc/DefaultSncLibraryLocator';
export type { SncArch } from './snc/libraryArchitectures';
export {
  type ISncProductProbe,
  SecureLoginClientProbe,
} from './snc/SecureLoginClientProbe';
export {
  SncLogonProvider,
  type SncLogonProviderConfig,
} from './snc/SncLogonProvider';
export { nodeSncSystem, type SncSystem } from './snc/SncSystem';
// SSO factory
export { SsoProviderFactory } from './sso/SsoProviderFactory';
export type { SsoProviderConfig, SsoProviderInstance } from './sso/types';
export type {
  BrowserCallbackStrategyOptions,
  CallbackStrategyOptions,
  ExternalCodeStrategyOptions,
  ManualStrategyOptions,
  StaticCodeStrategyOptions,
} from './strategies';
// Authorization strategies — or bring your own IAuthorizationStrategy.
export {
  asOidcResult,
  BrowserCallbackStrategy,
  browserCallbackStrategy,
  DEFAULT_CALLBACK_PORT,
  DEFAULT_LOGIN_TIMEOUT_MS,
  externalCodeStrategy,
  manualPasscodeStrategy,
  manualPasteStrategy,
  manualSamlResponseStrategy,
  oidcCallbackStrategy,
  samlCallbackStrategy,
  staticCodeStrategy,
} from './strategies';
// SAML assertion validation — the two shipped validators and the replay store,
// or bring your own IAssertionValidator / IAssertionReplayStore.
export {
  createSignedAssertionValidator,
  createSignedResponseValidator,
  type ShippedValidatorOptions,
} from './validation/assertionValidator';
export {
  createInMemoryReplayStore,
  defaultReplayStore,
} from './validation/inMemoryReplayStore';
