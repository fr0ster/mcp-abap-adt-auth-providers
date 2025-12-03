# @mcp-abap-adt/auth-providers

Token providers for MCP ABAP ADT auth-broker - XSUAA and BTP token providers.

## Overview

This package provides token provider implementations for the `@mcp-abap-adt/auth-broker` package:

- **XsuaaTokenProvider** - Uses client_credentials grant type (no browser required)
- **BtpTokenProvider** - Uses browser-based OAuth2 or refresh token flow

## Installation

```bash
npm install @mcp-abap-adt/auth-providers
```

## Usage

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

## License

MIT

