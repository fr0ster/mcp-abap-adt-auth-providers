# @mcp-abap-adt/auth-providers

Token providers for MCP ABAP ADT auth-broker - XSUAA and BTP token providers.

This package provides token provider implementations for the `@mcp-abap-adt/auth-broker` package.

## Installation

```bash
npm install @mcp-abap-adt/auth-providers
```

## Overview

This package implements the `ITokenProvider` interface from `@mcp-abap-adt/auth-broker`:

- **XsuaaTokenProvider** - Uses `client_credentials` grant type (no browser required)
- **BtpTokenProvider** - Uses browser-based OAuth2 or refresh token flow

## Usage

### Basic Usage

```typescript
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import { XsuaaTokenProvider, BtpTokenProvider } from '@mcp-abap-adt/auth-providers';

// Use XSUAA provider (client_credentials)
const xsuaaBroker = new AuthBroker({
  tokenProvider: new XsuaaTokenProvider(),
}, 'none'); // Browser not needed

// Use BTP provider (browser OAuth2 or refresh token)
const btpBroker = new AuthBroker({
  tokenProvider: new BtpTokenProvider(),
});
```

### With Stores

**Important**: BTP and ABAP are different entities:
- **BTP** (base BTP) - uses `BtpServiceKeyStore` and `BtpSessionStore` (without `sapUrl`)
- **ABAP** - uses `AbapServiceKeyStore` and `AbapSessionStore` (with `sapUrl`)

```typescript
import { AuthBroker } from '@mcp-abap-adt/auth-broker';
import { XsuaaTokenProvider, BtpTokenProvider } from '@mcp-abap-adt/auth-providers';
import { 
  XsuaaServiceKeyStore, 
  XsuaaSessionStore,
  BtpServiceKeyStore,
  BtpSessionStore,
  AbapServiceKeyStore,
  AbapSessionStore 
} from '@mcp-abap-adt/auth-stores';

// XSUAA provider with stores
const xsuaaServiceKeyStore = new XsuaaServiceKeyStore('/path/to/service-keys');
const xsuaaSessionStore = new XsuaaSessionStore('/path/to/sessions');

const xsuaaBroker = new AuthBroker({
  serviceKeyStore: xsuaaServiceKeyStore,
  sessionStore: xsuaaSessionStore,
  tokenProvider: new XsuaaTokenProvider(),
}, 'none');

// BTP provider with stores (base BTP, without sapUrl)
const btpServiceKeyStore = new BtpServiceKeyStore('/path/to/service-keys');
const btpSessionStore = new BtpSessionStore('/path/to/sessions');

const btpBroker = new AuthBroker({
  serviceKeyStore: btpServiceKeyStore,
  sessionStore: btpSessionStore,
  tokenProvider: new BtpTokenProvider(),
});

// ABAP provider with stores (with sapUrl)
const abapServiceKeyStore = new AbapServiceKeyStore('/path/to/service-keys');
const abapSessionStore = new AbapSessionStore('/path/to/sessions');

const abapBroker = new AuthBroker({
  serviceKeyStore: abapServiceKeyStore,
  sessionStore: abapSessionStore,
  tokenProvider: new BtpTokenProvider(), // BtpTokenProvider works for ABAP too
});
```

### Token Providers

#### XsuaaTokenProvider

Uses `client_credentials` grant type - no browser interaction required:

```typescript
import { XsuaaTokenProvider } from '@mcp-abap-adt/auth-providers';
import type { IAuthorizationConfig } from '@mcp-abap-adt/auth-broker';

const provider = new XsuaaTokenProvider();

const authConfig: IAuthorizationConfig = {
  uaaUrl: 'https://...authentication...hana.ondemand.com',
  uaaClientId: '...',
  uaaClientSecret: '...',
};

const result = await provider.getConnectionConfig(authConfig, {
  logger: defaultLogger,
});

// result.connectionConfig.authorizationToken contains the JWT token
// result.refreshToken is undefined (client_credentials doesn't provide refresh tokens)
```

#### BtpTokenProvider

Uses browser-based OAuth2 flow or refresh token:

```typescript
import { BtpTokenProvider } from '@mcp-abap-adt/auth-providers';
import type { IAuthorizationConfig } from '@mcp-abap-adt/auth-broker';

const provider = new BtpTokenProvider();

const authConfig: IAuthorizationConfig = {
  uaaUrl: 'https://...authentication...hana.ondemand.com',
  uaaClientId: '...',
  uaaClientSecret: '...',
  refreshToken: '...', // Optional - if provided, uses refresh flow instead of browser
};

// If refreshToken is provided, uses refresh flow (no browser)
// Otherwise, opens browser for OAuth2 authorization
const result = await provider.getConnectionConfig(authConfig, {
  logger: defaultLogger,
  browser: 'system', // 'system', 'none', or undefined
});

// result.connectionConfig.authorizationToken contains the JWT token
// result.refreshToken contains refresh token (if browser flow was used)
```

### Token Validation

Both providers support token validation:

```typescript
const isValid = await provider.validateToken(token, serviceUrl);
// Returns true if token is valid (200-299 status), false otherwise
```

## Testing

The package includes both unit tests (with mocks) and integration tests (with real files and services).

### Unit Tests

```bash
npm test
```

### Integration Tests

Integration tests work with real files from `tests/test-config.yaml`:

1. Copy `tests/test-config.yaml.template` to `tests/test-config.yaml`
2. Fill in real paths, destinations, and URLs
3. Run tests - integration tests will use real services if configured

```yaml
auth_broker:
  paths:
    service_keys_dir: ~/.config/mcp-abap-adt/service-keys/
    sessions_dir: ~/.config/mcp-abap-adt/sessions/
  abap:
    destination: "TRIAL"  # For ABAP tests (uses AbapServiceKeyStore, AbapSessionStore)
  xsuaa:
    btp_destination: "mcp"  # For BTP tests (uses BtpServiceKeyStore, BtpSessionStore)
    mcp_url: "https://..."
```

Integration tests will skip if `test-config.yaml` is not configured or contains placeholder values.

**Note**: 
- BTP integration tests use `xsuaa.btp_destination` and require `BtpServiceKeyStore`/`BtpSessionStore` (without `sapUrl`)
- ABAP integration tests use `abap.destination` and require `AbapServiceKeyStore`/`AbapSessionStore` (with `sapUrl`)
- BTP/ABAP integration tests may open a browser for authentication if no refresh token is available. This is expected behavior.

## Dependencies

- `@mcp-abap-adt/auth-broker` (^0.1.6) - Interface definitions
- `@mcp-abap-adt/auth-stores` (^0.1.2) - Store implementations
- `@mcp-abap-adt/connection` (^0.1.13) - Connection utilities
- `@mcp-abap-adt/logger` (^0.1.0) - Logging utilities
- `axios` - HTTP client
- `express` - OAuth2 callback server
- `open` - Browser opening utility

## License

MIT
