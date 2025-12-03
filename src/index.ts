/**
 * @mcp-abap-adt/auth-providers
 * Token providers for MCP ABAP ADT auth-broker
 * 
 * Provides XSUAA and BTP token providers
 */

// Token providers
export { XsuaaTokenProvider } from './providers/XsuaaTokenProvider';
export { BtpTokenProvider } from './providers/BtpTokenProvider';

// Auth functions (for advanced usage)
export { startBrowserAuth } from './auth/browserAuth';
export { getTokenWithClientCredentials } from './auth/clientCredentialsAuth';
export { refreshJwtToken } from './auth/tokenRefresher';

// Types
export type { ClientCredentialsResult } from './auth/clientCredentialsAuth';
export type { TokenRefreshResult } from './auth/tokenRefresher';

