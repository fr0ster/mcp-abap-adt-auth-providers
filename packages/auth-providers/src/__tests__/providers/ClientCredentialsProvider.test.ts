/**
 * Integration tests for ClientCredentialsProvider
 * Tests with real service keys from test-config.yaml
 *
 * Test scenarios:
 * 1. Only service key - should get token via client_credentials
 * 2. Service key + cached valid token - should use cached token
 * 3. Service key + expired cached token - should get new token via client_credentials
 */

import assert from 'node:assert/strict';
import * as dns from 'node:dns/promises';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { describe, it } from 'node:test';
import { AbapServiceKeyStore } from '@mcp-abap-adt/auth-stores';
import { AUTH_TYPE_CLIENT_CREDENTIALS } from '@mcp-abap-adt/interfaces-auth';
import { ClientCredentialsProvider } from '../../providers/ClientCredentialsProvider';
import { refreshThenLogin } from '../../renewal';
import {
  getAbapDestination,
  getServiceKeysDir,
  hasRealConfig,
  loadTestConfig,
} from '../helpers/configHelpers';

const canResolveHost = async (url: string): Promise<boolean> => {
  try {
    const hostname = new URL(url).hostname;
    await dns.lookup(hostname);
    return true;
  } catch {
    return false;
  }
};

// Helper to create expired JWT token
const createExpiredJWT = (): string => {
  const header = Buffer.from(
    JSON.stringify({ alg: 'RS256', typ: 'JWT' }),
  ).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({ exp: Math.floor(Date.now() / 1000) - 3600 }), // Expired 1 hour ago
  ).toString('base64url');
  return `${header}.${payload}.signature`;
};

// Helper to create valid JWT token
const createValidJWT = (): string => {
  const header = Buffer.from(
    JSON.stringify({ alg: 'RS256', typ: 'JWT' }),
  ).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600 }), // Valid for 1 hour
  ).toString('base64url');
  return `${header}.${payload}.signature`;
};

describe('ClientCredentialsProvider', () => {
  const config = loadTestConfig();
  const destination = getAbapDestination(config);
  const serviceKeysDir = getServiceKeysDir(config);
  const hasRealConfigValue = hasRealConfig(config, 'abap');

  describe('Scenario 1: Only service key', () => {
    it('should get token via client_credentials when no cached token', async () => {
      if (!hasRealConfigValue) {
        console.warn('⚠️  Skipping integration test - no real config');
        return;
      }

      if (!destination || !serviceKeysDir) {
        console.warn('⚠️  Skipping integration test - missing required config');
        return;
      }

      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);

      const authConfig =
        await serviceKeyStore.getAuthorizationConfig(destination);
      if (!authConfig) {
        throw new Error('Failed to load authorization config from service key');
      }
      if (!(await canResolveHost(authConfig.uaaUrl!))) {
        console.warn('⚠️  Skipping integration test - UAA host not resolvable');
        return;
      }
      if (!(await canResolveHost(authConfig.uaaUrl!))) {
        console.warn('⚠️  Skipping integration test - UAA host not resolvable');
        return;
      }

      // Create provider with only service key (no cached token)
      const provider = new ClientCredentialsProvider({
        renewal: refreshThenLogin(),
        uaaUrl: authConfig.uaaUrl!,
        clientId: authConfig.uaaClientId!,
        clientSecret: authConfig.uaaClientSecret!,
      });

      // Provider should get token via client_credentials
      const tokens = await provider.getTokens();
      assert.notEqual(tokens.authorizationToken, undefined);
      assert.equal(tokens.authType, AUTH_TYPE_CLIENT_CREDENTIALS);
      assert.equal(tokens.refreshToken, undefined); // client_credentials doesn't provide refresh token
    });
  });

  describe('Scenario 2: Service key + cached valid token', () => {
    it('should use cached token when token is valid', async () => {
      if (!hasRealConfigValue) {
        console.warn('⚠️  Skipping integration test - no real config');
        return;
      }

      if (!destination || !serviceKeysDir) {
        console.warn('⚠️  Skipping integration test - missing required config');
        return;
      }

      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);

      const authConfig =
        await serviceKeyStore.getAuthorizationConfig(destination);
      if (!authConfig) {
        throw new Error('Failed to load authorization config from service key');
      }
      if (!(await canResolveHost(authConfig.uaaUrl!))) {
        console.warn('⚠️  Skipping integration test - UAA host not resolvable');
        return;
      }

      // Create provider with valid cached token
      const validToken = createValidJWT();
      const provider = new ClientCredentialsProvider({
        renewal: refreshThenLogin(),
        uaaUrl: authConfig.uaaUrl!,
        clientId: authConfig.uaaClientId!,
        clientSecret: authConfig.uaaClientSecret!,
      });

      // Manually set token in provider (simulating cached token)
      (provider as any).authorizationToken = validToken;
      (provider as any).expiresAt = Date.now() + 3600 * 1000;

      // Provider should return cached token
      const tokens = await provider.getTokens();
      assert.equal(tokens.authorizationToken, validToken);
      assert.equal(tokens.authType, AUTH_TYPE_CLIENT_CREDENTIALS);
    });
  });

  describe('Scenario 3: Service key + expired cached token', () => {
    it('should get new token via client_credentials when cached token is expired', async () => {
      if (!hasRealConfigValue) {
        console.warn('⚠️  Skipping integration test - no real config');
        return;
      }

      if (!destination || !serviceKeysDir) {
        console.warn('⚠️  Skipping integration test - missing required config');
        return;
      }

      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);

      const authConfig =
        await serviceKeyStore.getAuthorizationConfig(destination);
      if (!authConfig) {
        throw new Error('Failed to load authorization config from service key');
      }
      if (!(await canResolveHost(authConfig.uaaUrl!))) {
        console.warn('⚠️  Skipping integration test - UAA host not resolvable');
        return;
      }

      // Create provider with expired cached token
      const expiredToken = createExpiredJWT();
      const provider = new ClientCredentialsProvider({
        renewal: refreshThenLogin(),
        uaaUrl: authConfig.uaaUrl!,
        clientId: authConfig.uaaClientId!,
        clientSecret: authConfig.uaaClientSecret!,
      });

      // Manually set expired token in provider (simulating expired cached token)
      (provider as any).authorizationToken = expiredToken;
      (provider as any).expiresAt = Date.now() - 3600 * 1000; // Expired 1 hour ago

      // Provider should get new token via client_credentials
      const tokens = await provider.getTokens();
      assert.notEqual(tokens.authorizationToken, undefined);
      assert.notEqual(tokens.authorizationToken, expiredToken); // Should be new token
      assert.equal(tokens.authType, AUTH_TYPE_CLIENT_CREDENTIALS);
      assert.equal(tokens.refreshToken, undefined); // client_credentials doesn't provide refresh token
    });
  });

  describe('Token caching', () => {
    it('should cache token and reuse it for subsequent calls', async () => {
      if (!hasRealConfigValue) {
        console.warn('⚠️  Skipping integration test - no real config');
        return;
      }

      if (!destination || !serviceKeysDir) {
        console.warn('⚠️  Skipping integration test - missing required config');
        return;
      }

      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);

      const authConfig =
        await serviceKeyStore.getAuthorizationConfig(destination);
      if (!authConfig) {
        throw new Error('Failed to load authorization config from service key');
      }
      if (!(await canResolveHost(authConfig.uaaUrl!))) {
        console.warn('⚠️  Skipping integration test - UAA host not resolvable');
        return;
      }

      const provider = new ClientCredentialsProvider({
        renewal: refreshThenLogin(),
        uaaUrl: authConfig.uaaUrl!,
        clientId: authConfig.uaaClientId!,
        clientSecret: authConfig.uaaClientSecret!,
      });

      // First call - should get token
      const firstTokens = await provider.getTokens();
      assert.notEqual(firstTokens.authorizationToken, undefined);

      // Second call - should return cached token (same token)
      const secondTokens = await provider.getTokens();
      assert.equal(
        secondTokens.authorizationToken,
        firstTokens.authorizationToken,
      );
      assert.equal(secondTokens.authType, AUTH_TYPE_CLIENT_CREDENTIALS);
    });
  });

  describe('Token validation', () => {
    it('should validate token expiration correctly', async () => {
      if (!hasRealConfigValue) {
        console.warn('⚠️  Skipping integration test - no real config');
        return;
      }

      if (!destination || !serviceKeysDir) {
        console.warn('⚠️  Skipping integration test - missing required config');
        return;
      }

      const serviceKeyStore = new AbapServiceKeyStore(serviceKeysDir);

      const authConfig =
        await serviceKeyStore.getAuthorizationConfig(destination);
      if (!authConfig) {
        throw new Error('Failed to load authorization config from service key');
      }

      const provider = new ClientCredentialsProvider({
        renewal: refreshThenLogin(),
        uaaUrl: authConfig.uaaUrl!,
        clientId: authConfig.uaaClientId!,
        clientSecret: authConfig.uaaClientSecret!,
      });

      // Test validation of expired token
      const expiredToken = createExpiredJWT();
      const isValidExpired = await provider.validateToken?.(expiredToken);
      assert.equal(isValidExpired, false);

      // Test validation of valid token
      const validToken = createValidJWT();
      const isValidValid = await provider.validateToken?.(validToken);
      assert.equal(isValidValid, true);
    });
  });
});
