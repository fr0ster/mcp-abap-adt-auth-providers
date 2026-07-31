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
export { withSamlCallbackServer } from './auth/saml2Auth';
// Errors
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
  DeviceFlowProviderConfig,
  OidcBrowserProviderConfig,
  OidcDeviceFlowProviderConfig,
  OidcPasswordProviderConfig,
  OidcTokenExchangeProviderConfig,
  Saml2BearerProviderConfig,
  Saml2PureProviderConfig,
} from './providers';
// Token Providers (stateful providers with automatic token lifecycle)
export {
  AuthorizationCodeProvider,
  BaseTokenProvider,
  ClientCredentialsProvider,
  DeviceFlowProvider,
  OidcBrowserProvider,
  OidcDeviceFlowProvider,
  OidcPasswordProvider,
  OidcTokenExchangeProvider,
  Saml2BearerProvider,
  Saml2PureProvider,
} from './providers';
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
  manualPasteStrategy,
  manualSamlResponseStrategy,
  oidcCallbackStrategy,
  samlCallbackStrategy,
  staticCodeStrategy,
} from './strategies';
