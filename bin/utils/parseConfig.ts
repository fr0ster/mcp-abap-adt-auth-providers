/**
 * Utility functions for parsing service keys and env files
 */

import {
  ABAP_AUTHORIZATION_VARS,
  ABAP_CONNECTION_VARS,
} from '@mcp-abap-adt/auth-stores';
import * as fs from 'node:fs';
import * as path from 'node:path';

export interface ServiceKey {
  // Format 1: ABAP Environment service key (nested uaa object)
  uaa?: {
    url?: string;
    clientid?: string;
    clientsecret?: string;
  };
  // Format 2: XSUAA/BTP service key (flat structure)
  url?: string;
  clientid?: string;
  clientsecret?: string;
  // ABAP service URL
  sap_url?: string;
}

export interface EnvConfig {
  // ABAP Connection vars
  [ABAP_CONNECTION_VARS.SERVICE_URL]?: string;
  [ABAP_CONNECTION_VARS.AUTHORIZATION_TOKEN]?: string;
  [ABAP_CONNECTION_VARS.USERNAME]?: string;
  [ABAP_CONNECTION_VARS.PASSWORD]?: string;
  [ABAP_CONNECTION_VARS.SAP_CLIENT]?: string;
  [ABAP_CONNECTION_VARS.SAP_LANGUAGE]?: string;
  // ABAP Authorization vars
  [ABAP_AUTHORIZATION_VARS.UAA_URL]?: string;
  [ABAP_AUTHORIZATION_VARS.UAA_CLIENT_ID]?: string;
  [ABAP_AUTHORIZATION_VARS.UAA_CLIENT_SECRET]?: string;
  [ABAP_AUTHORIZATION_VARS.REFRESH_TOKEN]?: string;
  // Legacy support (for backward compatibility)
  UAA_URL?: string;
  UAA_CLIENT_ID?: string;
  UAA_CLIENT_SECRET?: string;
  SAP_URL?: string;
  SERVICE_URL?: string;
  AUTHORIZATION_TOKEN?: string;
  REFRESH_TOKEN?: string;
}

/**
 * Parse service key from JSON file
 */
export function parseServiceKey(filePath: string): ServiceKey {
  const fullPath = path.resolve(filePath);
  if (!fs.existsSync(fullPath)) {
    throw new Error(`Service key file not found: ${fullPath}`);
  }

  const content = fs.readFileSync(fullPath, 'utf8');
  try {
    return JSON.parse(content) as ServiceKey;
  } catch (error) {
    throw new Error(
      `Failed to parse service key file: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Parse .env file
 */
export function parseEnvFile(filePath: string): EnvConfig {
  const fullPath = path.resolve(filePath);
  if (!fs.existsSync(fullPath)) {
    throw new Error(`Env file not found: ${fullPath}`);
  }

  const content = fs.readFileSync(fullPath, 'utf8');
  const config: EnvConfig = {};

  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    const match = trimmed.match(/^([^=]+)=(.*)$/);
    if (match) {
      const key = match[1].trim();
      const value = match[2].trim().replace(/^["']|["']$/g, '');
      (config as Record<string, string>)[key] = value;
    }
  }

  return config;
}

/**
 * Get UAA credentials from service key or env file
 * Supports two service key formats:
 * 1. ABAP Environment: nested uaa object (uaa.url, uaa.clientid, uaa.clientsecret)
 * 2. XSUAA/BTP flat: top-level fields (url, clientid, clientsecret)
 */
export function getUaaCredentials(
  serviceKey?: ServiceKey,
  envConfig?: EnvConfig,
): {
  uaaUrl: string;
  clientId: string;
  clientSecret: string;
} {
  if (serviceKey) {
    // Format 1: ABAP Environment service key with nested uaa object
    if (serviceKey.uaa?.url && serviceKey.uaa?.clientid && serviceKey.uaa?.clientsecret) {
      return {
        uaaUrl: serviceKey.uaa.url,
        clientId: serviceKey.uaa.clientid,
        clientSecret: serviceKey.uaa.clientsecret,
      };
    }

    // Format 2: XSUAA/BTP flat service key (url is UAA URL, no nested uaa object)
    if (serviceKey.url && serviceKey.clientid && serviceKey.clientsecret) {
      return {
        uaaUrl: serviceKey.url,
        clientId: serviceKey.clientid,
        clientSecret: serviceKey.clientsecret,
      };
    }

    // Try to provide helpful error message
    const hasUaa = !!serviceKey.uaa;
    const hasFlat = !!(serviceKey.clientid || serviceKey.clientsecret);
    if (hasUaa) {
      throw new Error(
        'Service key (ABAP format) missing required UAA fields: uaa.url, uaa.clientid, uaa.clientsecret',
      );
    } else if (hasFlat) {
      throw new Error(
        'Service key (XSUAA format) missing required fields: url, clientid, clientsecret',
      );
    } else {
      throw new Error(
        'Service key format not recognized. Expected either ABAP format (uaa.url, uaa.clientid, uaa.clientsecret) or XSUAA format (url, clientid, clientsecret)',
      );
    }
  }

  if (envConfig) {
    // Use constants from auth-stores, fallback to legacy names
    const uaaUrl =
      envConfig[ABAP_AUTHORIZATION_VARS.UAA_URL] || envConfig.UAA_URL;
    const clientId =
      envConfig[ABAP_AUTHORIZATION_VARS.UAA_CLIENT_ID] ||
      envConfig.UAA_CLIENT_ID;
    const clientSecret =
      envConfig[ABAP_AUTHORIZATION_VARS.UAA_CLIENT_SECRET] ||
      envConfig.UAA_CLIENT_SECRET;

    if (!uaaUrl || !clientId || !clientSecret) {
      throw new Error(
        `Env file missing required UAA fields: ${ABAP_AUTHORIZATION_VARS.UAA_URL}, ${ABAP_AUTHORIZATION_VARS.UAA_CLIENT_ID}, ${ABAP_AUTHORIZATION_VARS.UAA_CLIENT_SECRET}`,
      );
    }

    return { uaaUrl, clientId, clientSecret };
  }

  throw new Error('No service key or env config provided');
}

/**
 * Convert ABAP URL to ABAP-Web URL for ADT reentrancy ticket
 * @param url Original URL (may contain .abap. or .abap-web.)
 * @returns URL with .abap-web. domain
 */
function convertToAbapWebUrl(url: string): string {
  // Replace .abap. with .abap-web. for ADT reentrancy ticket
  return url.replace(/\.abap\./g, '.abap-web.');
}

/**
 * Get service URL from service key or env file
 * For ADT, converts .abap. to .abap-web. if needed
 */
export function getServiceUrl(
  serviceKey?: ServiceKey,
  envConfig?: EnvConfig,
  forAdt: boolean = false,
): string | undefined {
  let url: string | undefined;

  if (serviceKey) {
    url = serviceKey.url || serviceKey.sap_url;
  } else if (envConfig) {
    // Use constants from auth-stores, fallback to legacy names
    url =
      envConfig[ABAP_CONNECTION_VARS.SERVICE_URL] ||
      envConfig.SAP_URL ||
      envConfig.SERVICE_URL;
  }

  if (url && forAdt) {
    url = convertToAbapWebUrl(url);
  }

  return url;
}

/**
 * Write tokens to .env file
 */
export function writeEnvFile(
  filePath: string,
  tokens: {
    authorizationToken?: string;
    refreshToken?: string;
    uaaUrl?: string;
    clientId?: string;
    clientSecret?: string;
    serviceUrl?: string;
  },
): void {
  const fullPath = path.resolve(filePath);
  const lines: string[] = [];

  // Read existing file if it exists
  const existing: EnvConfig = fs.existsSync(fullPath)
    ? parseEnvFile(fullPath)
    : {};

  // Update with new tokens using constants from auth-stores
  if (tokens.authorizationToken) {
    existing[ABAP_CONNECTION_VARS.AUTHORIZATION_TOKEN] =
      tokens.authorizationToken;
  }
  // Update refresh token only if provided (don't remove existing if not provided)
  if (tokens.refreshToken) {
    existing[ABAP_AUTHORIZATION_VARS.REFRESH_TOKEN] = tokens.refreshToken;
  }
  if (tokens.uaaUrl) {
    existing[ABAP_AUTHORIZATION_VARS.UAA_URL] = tokens.uaaUrl;
  }
  if (tokens.clientId) {
    existing[ABAP_AUTHORIZATION_VARS.UAA_CLIENT_ID] = tokens.clientId;
  }
  if (tokens.clientSecret) {
    existing[ABAP_AUTHORIZATION_VARS.UAA_CLIENT_SECRET] = tokens.clientSecret;
  }
  if (tokens.serviceUrl) {
    // Use SAP_URL as the standard name for ABAP systems
    existing[ABAP_CONNECTION_VARS.SERVICE_URL] = tokens.serviceUrl;
  }

  // Write all values
  for (const [key, value] of Object.entries(existing)) {
    if (value) {
      lines.push(`${key}=${value}`);
    }
  }

  // Ensure directory exists
  const dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  fs.writeFileSync(fullPath, lines.join('\n') + '\n', 'utf8');
}

