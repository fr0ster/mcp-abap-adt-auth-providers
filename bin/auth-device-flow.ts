#!/usr/bin/env tsx
/**
 * Device Flow Provider Test Command
 */

import { DeviceFlowProvider } from '../src/providers/DeviceFlowProvider';
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
  let scope: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--service-key' && args[i + 1]) {
      serviceKeyPath = args[++i];
    } else if (arg === '--input-env' && args[i + 1]) {
      inputEnvPath = args[++i];
    } else if (arg === '--output-env' && args[i + 1]) {
      outputEnvPath = args[++i];
    } else if (arg === '--scope' && args[i + 1]) {
      scope = args[++i];
    } else if (arg === '--help' || arg === '-h') {
      console.log(`
Usage: auth-device-flow [options]

Options:
  --service-key <path>    Path to service key JSON file
  --input-env <path>      Path to .env file for reading existing tokens (for refresh)
  --output-env <path>     Path to .env file for saving tokens
  --scope <scope>         Optional scope (space-separated)
  --help, -h              Show this help message
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
    // Read config from service key or input env
    const serviceKey = serviceKeyPath ? parseServiceKey(serviceKeyPath) : undefined;
    const inputEnv = inputEnvPath ? parseEnvFile(inputEnvPath) : undefined;
    const { uaaUrl, clientId, clientSecret } = getUaaCredentials(serviceKey, inputEnv);

    // Read existing tokens from input env if provided
    const existingAccessToken = inputEnv?.AUTHORIZATION_TOKEN;
    const existingRefreshToken = inputEnv?.REFRESH_TOKEN;

    const provider = new DeviceFlowProvider({
      uaaUrl,
      clientId,
      clientSecret,
      scope,
      accessToken: existingAccessToken,
      refreshToken: existingRefreshToken,
    });

    console.log('🔐 Getting tokens using Device Flow...');
    if (serviceKeyPath) {
      console.log(`📁 Service Key: ${serviceKeyPath}`);
    }
    if (inputEnvPath) {
      console.log(`📁 Input Env: ${inputEnvPath}`);
    }
    console.log(`💾 Output Env: ${outputEnvPath}\n`);

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

