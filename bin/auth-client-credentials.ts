#!/usr/bin/env tsx
/**
 * Client Credentials Provider Test Command
 *
 * Gets tokens using client_credentials grant type
 */

import { ClientCredentialsProvider } from '../src/providers/ClientCredentialsProvider';
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

  // Parse arguments
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--service-key' && args[i + 1]) {
      serviceKeyPath = args[++i];
    } else if (arg === '--input-env' && args[i + 1]) {
      inputEnvPath = args[++i];
    } else if (arg === '--output-env' && args[i + 1]) {
      outputEnvPath = args[++i];
    } else if (arg === '--help' || arg === '-h') {
      console.log(`
Usage: auth-client-credentials [options]

Options:
  --service-key <path>    Path to service key JSON file
  --input-env <path>      Path to .env file for reading credentials
  --output-env <path>     Path to .env file for saving tokens (required)
  --help, -h              Show this help message

Example:
  auth-client-credentials --service-key ./service-key.json --output-env ./tokens.env
  auth-client-credentials --input-env ./tokens.env --output-env ./tokens.env
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

    // Create provider
    const provider = new ClientCredentialsProvider({
      uaaUrl,
      clientId,
      clientSecret,
    });

    console.log('🔐 Getting tokens using Client Credentials flow...');
    if (serviceKeyPath) {
      console.log(`📁 Service Key: ${serviceKeyPath}`);
    }
    if (inputEnvPath) {
      console.log(`📁 Input Env: ${inputEnvPath}`);
    }
    console.log(`💾 Output Env: ${outputEnvPath}\n`);

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

