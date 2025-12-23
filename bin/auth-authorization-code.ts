#!/usr/bin/env tsx
/**
 * Authorization Code Provider Test Command
 *
 * Gets tokens using authorization_code grant type
 */

import {
  ABAP_AUTHORIZATION_VARS,
  ABAP_CONNECTION_VARS,
} from '@mcp-abap-adt/auth-stores';
import { AuthorizationCodeProvider } from '../src/providers/AuthorizationCodeProvider';
import {
  getUaaCredentials,
  parseEnvFile,
  parseServiceKey,
  writeEnvFile,
} from './utils/parseConfig';

async function main() {
  const args = process.argv.slice(2);
  let serviceKeyPath: string | undefined;
  let inputEnvPath: string | undefined;
  let outputEnvPath: string | undefined;
  let browser: string = 'none';
  let port: number = 3001;
  let authorizationUrl: string | undefined;

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--service-key' && args[i + 1]) {
      serviceKeyPath = args[++i];
    } else if (arg === '--input-env' && args[i + 1]) {
      inputEnvPath = args[++i];
    } else if (arg === '--output-env' && args[i + 1]) {
      outputEnvPath = args[++i];
    } else if (arg === '--browser' && args[i + 1]) {
      browser = args[++i];
    } else if (arg === '--port' && args[i + 1]) {
      port = parseInt(args[++i], 10);
    } else if (arg === '--auth-url' && args[i + 1]) {
      authorizationUrl = args[++i];
    } else if (arg === '--help' || arg === '-h') {
      console.log(`
Usage: auth-authorization-code [options]

Options:
  --service-key <path>    Path to service key JSON file
  --input-env <path>      Path to .env file for reading existing tokens (for refresh)
  --output-env <path>     Path to .env file for saving tokens (required)
  --browser <type>        Browser type (auto, system, chrome, none) [default: none]
  --port <number>         Callback server port [default: 3001]
  --auth-url <url>        Pre-built authorization URL
  --help, -h              Show this help message

Example:
  auth-authorization-code --service-key ./service-key.json --output-env ./tokens.env --browser auto
  auth-authorization-code --input-env ./tokens.env --output-env ./tokens.env --browser none
      `);
      process.exit(0);
    }
  }

  if (!serviceKeyPath && !inputEnvPath) {
    console.error('❌ Error: Either --service-key or --input-env must be provided');
    process.exit(1);
  }

  if (!outputEnvPath) {
    console.error('❌ Error: --output-env is required to save tokens');
    process.exit(1);
  }

  try {
    // Parse config
    const serviceKey = serviceKeyPath ? parseServiceKey(serviceKeyPath) : undefined;
    const inputEnv = inputEnvPath ? parseEnvFile(inputEnvPath) : undefined;
    const { uaaUrl, clientId, clientSecret } = getUaaCredentials(serviceKey, inputEnv);

    // Read existing tokens from input env if provided (use constants, fallback to legacy)
    const existingRefreshToken =
      inputEnv?.[ABAP_AUTHORIZATION_VARS.REFRESH_TOKEN] ||
      inputEnv?.REFRESH_TOKEN;

    // Build authorization URL if not provided
    if (!authorizationUrl) {
      const redirectUri = `http://localhost:${port}/callback`;
      authorizationUrl = `${uaaUrl}/oauth/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code`;
    }

    // Create provider
    const provider = new AuthorizationCodeProvider({
      authorizationUrl,
      uaaUrl,
      clientId,
      clientSecret,
      browser,
      redirectPort: port,
      refreshToken: existingRefreshToken,
    });

    console.log('🔐 Getting tokens using Authorization Code flow...');
    if (serviceKeyPath) {
      console.log(`📁 Service Key: ${serviceKeyPath}`);
    }
    if (inputEnvPath) {
      console.log(`📁 Input Env: ${inputEnvPath}`);
    }
    console.log(`💾 Output Env: ${outputEnvPath}`);
    console.log(`🌐 Browser: ${browser}`);
    console.log(`🔗 Authorization URL: ${authorizationUrl}\n`);

    // Get tokens
    const result = await provider.getTokens();

    // Save tokens to output env file
    writeEnvFile(outputEnvPath, {
      authorizationToken: result.authorizationToken,
      refreshToken: result.refreshToken,
      uaaUrl,
      clientId,
      clientSecret,
    });

    console.log('✅ Tokens obtained and saved successfully!');
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`🔑 Authorization Token: ${result.authorizationToken.substring(0, 50)}...`);
    if (result.refreshToken) {
      console.log(`🔄 Refresh Token: ${result.refreshToken.substring(0, 50)}...`);
    }
    console.log(`📋 Auth Type: ${result.authType}`);
    if (result.expiresIn) {
      console.log(`⏰ Expires In: ${result.expiresIn} seconds`);
    }
    console.log(`💾 Saved to: ${outputEnvPath}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  } catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}

main();

