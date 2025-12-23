# Token Provider Refactoring Proposal

## Current Problems

### Problem 1: Authorization URL doesn't need service key
Currently, when using `--auth-url`, we still require `--service-key` for token exchange. But the initial authorization flow only needs the URL - service key is only needed for exchanging the authorization code for tokens.

### Problem 2: Provider structure is incorrect
Current structure has multiple methods (`getConnectionConfig`, `refreshTokenFromSession`, `refreshTokenFromServiceKey`) that are called externally, making the provider stateless and requiring external logic to manage token lifecycle.

## Proposed Architecture

### 1. New Interface: `ITokenProvider`

```typescript
export interface ITokenResult {
  authorizationToken: string;
  refreshToken?: string;
  authType: 'authorization_code' | 'client_credentials';
  expiresIn?: number; // seconds until expiration
}

export interface ITokenProvider {
  /**
   * Get tokens with automatic refresh/relogin logic
   * Checks token expiration, refreshes if needed, or triggers login
   */
  getTokens(): Promise<ITokenResult>;
}
```

### 2. Base Token Provider (Abstract Class)

```typescript
export abstract class BaseTokenProvider implements ITokenProvider {
  protected authorizationToken?: string;
  protected refreshToken?: string;
  protected expiresAt?: number; // timestamp
  
  /**
   * Check if current token is valid (not expired)
   */
  protected isTokenValid(): boolean {
    if (!this.authorizationToken || !this.expiresAt) {
      return false;
    }
    const bufferMs = 60 * 1000; // 60 second buffer
    return Date.now() < (this.expiresAt - bufferMs);
  }
  
  /**
   * Abstract method to perform initial login/authorization
   */
  protected abstract performLogin(): Promise<ITokenResult>;
  
  /**
   * Abstract method to refresh token
   */
  protected abstract performRefresh(): Promise<ITokenResult>;
  
  /**
   * Main method - handles token lifecycle
   */
  async getTokens(): Promise<ITokenResult> {
    // If token is valid, return cached
    if (this.isTokenValid()) {
      return {
        authorizationToken: this.authorizationToken!,
        refreshToken: this.refreshToken,
        authType: this.getAuthType(),
        expiresIn: Math.floor((this.expiresAt! - Date.now()) / 1000),
      };
    }
    
    // Try refresh if we have refresh token
    if (this.refreshToken) {
      try {
        const result = await this.performRefresh();
        this.updateTokens(result);
        return result;
      } catch (error) {
        // Refresh failed - need to login
        // Clear refresh token as it's invalid
        this.refreshToken = undefined;
        // Fall through to login
      }
    }
    
    // Perform login
    const result = await this.performLogin();
    this.updateTokens(result);
    return result;
  }
  
  protected updateTokens(result: ITokenResult): void {
    this.authorizationToken = result.authorizationToken;
    this.refreshToken = result.refreshToken;
    if (result.expiresIn) {
      this.expiresAt = Date.now() + (result.expiresIn * 1000);
    }
  }
  
  protected abstract getAuthType(): 'authorization_code' | 'client_credentials';
}
```

### 3. Authorization Code Provider

```typescript
export interface AuthorizationCodeProviderConfig {
  // Option 1: URL + browser (for initial login)
  authorizationUrl?: string;
  browser?: string; // 'auto', 'system', 'chrome', etc.
  redirectPort?: number; // default: 3001
  
  // Option 2: URL + tokens (for refresh scenario)
  accessToken?: string;
  refreshToken?: string;
  
  // Required for token exchange
  uaaUrl: string;
  clientId: string;
  clientSecret: string;
}

export class AuthorizationCodeProvider extends BaseTokenProvider {
  private config: AuthorizationCodeProviderConfig;
  
  constructor(config: AuthorizationCodeProviderConfig) {
    super();
    this.config = config;
    
    // Initialize from provided tokens if available
    if (config.accessToken) {
      this.authorizationToken = config.accessToken;
      // Parse expiration from JWT
      this.expiresAt = this.parseExpirationFromJWT(config.accessToken);
    }
    if (config.refreshToken) {
      this.refreshToken = config.refreshToken;
    }
  }
  
  protected getAuthType(): 'authorization_code' {
    return 'authorization_code';
  }
  
  protected async performLogin(): Promise<ITokenResult> {
    if (!this.config.authorizationUrl) {
      throw new Error('Authorization URL is required for login');
    }
    
    if (!this.config.browser) {
      throw new Error('Browser parameter is required for authorization_code flow');
    }
    
    // Start browser authentication
    const result = await startBrowserAuth(
      {
        uaaUrl: this.config.uaaUrl,
        uaaClientId: this.config.clientId,
        uaaClientSecret: this.config.clientSecret,
        authorizationUrl: this.config.authorizationUrl, // Pass pre-built URL
      },
      this.config.browser,
      undefined, // logger
      this.config.redirectPort || 3001,
    );
    
    // Parse expiration from JWT
    const expiresIn = this.parseExpirationFromJWT(result.accessToken);
    
    return {
      authorizationToken: result.accessToken,
      refreshToken: result.refreshToken,
      authType: 'authorization_code',
      expiresIn,
    };
  }
  
  protected async performRefresh(): Promise<ITokenResult> {
    if (!this.refreshToken) {
      throw new Error('Refresh token is required for refresh');
    }
    
    // Try refresh first
    try {
      const result = await refreshJwtToken(
        this.refreshToken,
        this.config.uaaUrl,
        this.config.clientId,
        this.config.clientSecret,
      );
      
      const expiresIn = this.parseExpirationFromJWT(result.accessToken);
      
      return {
        authorizationToken: result.accessToken,
        refreshToken: result.refreshToken || this.refreshToken, // Keep old if new not provided
        authType: 'authorization_code',
        expiresIn,
      };
    } catch (error) {
      // Refresh failed - try login with browser if URL provided
      if (this.config.authorizationUrl && this.config.browser) {
        // Fall back to browser login
        return await this.performLogin();
      }
      
      // No URL/browser - throw error
      throw new Error(
        'Tokens expired, refresh failed. Please login through browser (provide authorizationUrl and browser).',
      );
    }
  }
  
  private parseExpirationFromJWT(token: string): number | undefined {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return undefined;
      
      const payload = parts[1];
      const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
      const padded = base64 + '=='.substring(0, (4 - (base64.length % 4)) % 4);
      const decoded = Buffer.from(padded, 'base64').toString('utf8');
      const claims = JSON.parse(decoded);
      
      if (claims.exp) {
        const expirationTime = claims.exp * 1000; // Convert to milliseconds
        const now = Date.now();
        return Math.floor((expirationTime - now) / 1000); // Return seconds
      }
    } catch {
      // Failed to parse
    }
    return undefined;
  }
}
```

### 4. Client Credentials Provider

```typescript
export interface ClientCredentialsProviderConfig {
  uaaUrl: string;
  clientId: string;
  clientSecret: string;
}

export class ClientCredentialsProvider extends BaseTokenProvider {
  private config: ClientCredentialsProviderConfig;
  
  constructor(config: ClientCredentialsProviderConfig) {
    super();
    this.config = config;
  }
  
  protected getAuthType(): 'client_credentials' {
    return 'client_credentials';
  }
  
  protected async performLogin(): Promise<ITokenResult> {
    const result = await getTokenWithClientCredentials(
      this.config.uaaUrl,
      this.config.clientId,
      this.config.clientSecret,
    );
    
    const expiresIn = result.expiresIn;
    
    return {
      authorizationToken: result.accessToken,
      refreshToken: undefined, // client_credentials doesn't provide refresh token
      authType: 'client_credentials',
      expiresIn,
    };
  }
  
  protected async performRefresh(): Promise<ITokenResult> {
    // For client_credentials, refresh is same as login (no refresh token)
    return await this.performLogin();
  }
}
```

## Provider Types Summary

| Provider | Grant Type | Browser Required | Refresh Token | Client Secret | Use Case |
|----------|------------|------------------|----------------|---------------|----------|
| `AuthorizationCodeProvider` | authorization_code | Yes | Yes | Required | Standard OAuth2 flow |
| `ClientCredentialsProvider` | client_credentials | No | No | Required | Service-to-service |

## Benefits

1. **Stateful providers**: Tokens are cached in the provider instance
2. **Automatic refresh**: Provider handles token lifecycle internally
3. **Simpler API**: One method `getTokens()` instead of multiple
4. **Better error handling**: Clear distinction between login failure and refresh failure
5. **No external lifecycle management**: AuthBroker doesn't need to manage token state
6. **Authorization URL independence**: Can use pre-built URL without service key for initial auth
7. **Multiple grant types**: Support for authorization_code and client_credentials
8. **Extensible**: Easy to add new grant types by extending BaseTokenProvider

## Migration Path

1. Create new interfaces and base class
2. Implement new providers alongside old ones
3. Update AuthBroker to use new providers
4. Deprecate old interface
5. Remove old implementations

## Error Messages

### Authorization Code Provider

**When only URL provided and login fails:**
```
Error: Failed to authenticate. Please check authorization URL and try again.
```

**When tokens provided and refresh fails:**
```
Error: Tokens expired, refresh failed. Please login through browser (provide authorizationUrl and browser).
```

## Usage Examples

### Authorization Code with URL only

```typescript
const provider = new AuthorizationCodeProvider({
  authorizationUrl: 'https://.../oauth/authorize?...',
  browser: 'auto',
  uaaUrl: 'https://...authentication...hana.ondemand.com',
  clientId: '...',
  clientSecret: '...',
});

const tokens = await provider.getTokens();
// Opens browser, waits for callback, returns tokens
```

### Client Credentials (service-to-service)

```typescript
const provider = new ClientCredentialsProvider({
  uaaUrl: 'https://...authentication...hana.ondemand.com',
  clientId: '...',
  clientSecret: '...',
});

const tokens = await provider.getTokens();
// Gets token, caches it, refreshes when expired
```
