# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `@mcp-abap-adt/auth-providers` - a TypeScript npm package that provides authentication token providers for SAP ABAP ADT via Model Context Protocol (MCP). It implements two token provider strategies:
- **XsuaaTokenProvider**: Uses client_credentials grant type (no browser required)
- **BtpTokenProvider**: Uses browser-based OAuth2 or refresh token flow

## Build Commands

```bash
npm run build        # Full clean build (rm dist + tsc)
npm run build:fast   # Fast incremental build
npm run test:check   # TypeScript type checking only
npm test             # Run all tests (uses --experimental-vm-modules)
```

To run a single test file:
```bash
npm test -- path/to/test.test.ts
```

Debug logging for tests:
```bash
DEBUG_AUTH_PROVIDERS=true npm test
DEBUG_BROWSER_AUTH=true npm test
LOG_LEVEL=debug npm test
```

## Architecture

### Core Design Principle

**Interface-only communication**: All interactions with external dependencies happen ONLY through interfaces from `@mcp-abap-adt/interfaces`. The package does not know about concrete implementation classes from other packages.

### Package Responsibilities

This package ONLY:
- Implements `ITokenProvider` interface
- Handles OAuth2 flows (browser-based, refresh token, client credentials)
- Obtains JWT tokens via HTTP requests to UAA endpoints
- Validates tokens by making HTTP requests to service endpoints

This package does NOT:
- Store tokens (handled by `@mcp-abap-adt/auth-stores`)
- Orchestrate authentication (handled by `@mcp-abap-adt/auth-broker`)
- Load service keys or manage sessions

### Module Structure

```
src/
├── index.ts                    # Exports: providers + error classes
├── providers/
│   ├── XsuaaTokenProvider.ts   # client_credentials grant (no browser)
│   └── BtpTokenProvider.ts     # OAuth2 browser flow + refresh tokens
├── auth/
│   ├── browserAuth.ts          # OAuth2 callback server with port management
│   ├── clientCredentialsAuth.ts
│   └── tokenRefresher.ts
└── errors/
    └── TokenProviderErrors.ts  # ValidationError, RefreshError, etc.
```

### Key Behaviors

**BtpTokenProvider**:
- Constructor accepts optional `browserAuthPort` (default: 3001)
- Automatic port selection if port busy (tries up to 10 ports)
- Process termination handlers (SIGTERM, SIGINT, SIGHUP) ensure port cleanup

**browserAuth.ts**:
- Express server for OAuth2 callback
- 5-minute authentication timeout
- Styled HTML feedback pages (success/error)

## Testing

**Unit tests**: Mock axios and external dependencies
**Integration tests**: Require `tests/test-config.yaml` (copy from template)

Integration tests are skipped if config file is missing. To run integration tests:
1. Copy `tests/test-config.yaml.template` to `tests/test-config.yaml`
2. Fill in real service keys, destinations, URLs
3. Run `npm test`

## Error Classes

All errors extend `TokenProviderError` with error codes from `@mcp-abap-adt/interfaces`:
- `ValidationError` - includes `missingFields[]`
- `RefreshError` - includes `cause?: Error`
- `SessionDataError`, `ServiceKeyError`, `BrowserAuthError`
